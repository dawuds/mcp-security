#!/usr/bin/env python3
"""
validate-schema.py — MCP Tool Schema Security Validator

Reads one or more MCP tool schema definitions (JSON Schema) and checks them
against security best practices. Poorly constrained schemas allow malformed,
oversized, or ambiguous inputs that can lead to denial-of-service, prompt
injection, or unintended tool behaviour.

Input file format — either:
  A single tool object:
    {"name": "my_tool", "inputSchema": { ... }}

  Or an array of tool objects:
    [
      {"name": "tool_a", "inputSchema": { ... }},
      {"name": "tool_b", "inputSchema": { ... }}
    ]

Usage:
    python validate-schema.py schema.json
    python validate-schema.py --json schema.json

Exit codes:
    0 — no HIGH severity findings
    1 — one or more HIGH severity findings
"""

import argparse
import json
import os
import sys
from typing import Any

# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------

TOOL_VERSION = "0.1.0"

# Severity levels and their display order (highest first)
SEVERITY_ORDER = ["HIGH", "MEDIUM", "LOW"]

# ANSI colour codes — disabled when not writing to a terminal
COLOURS = {
    "HIGH":   "\033[91m",
    "MEDIUM": "\033[93m",
    "LOW":    "\033[94m",
    "RESET":  "\033[0m",
    "BOLD":   "\033[1m",
    "DIM":    "\033[2m",
    "GREEN":  "\033[92m",
}

# JSON Schema type values that represent numeric types
NUMERIC_TYPES = {"number", "integer"}

# ---------------------------------------------------------------------------
# Data model
# ---------------------------------------------------------------------------


class Finding:
    """A single schema security finding."""

    def __init__(
        self,
        check_id: str,
        severity: str,
        tool_name: str | None,
        field_path: str | None,
        message: str,
        detail: str | None = None,
    ) -> None:
        self.check_id = check_id
        self.severity = severity
        self.tool_name = tool_name
        self.field_path = field_path   # e.g. "inputSchema.properties.query"
        self.message = message
        self.detail = detail

    def to_dict(self) -> dict[str, Any]:
        d: dict[str, Any] = {
            "check_id": self.check_id,
            "severity": self.severity,
            "tool": self.tool_name,
            "field_path": self.field_path,
            "message": self.message,
        }
        if self.detail:
            d["detail"] = self.detail
        return d


# ---------------------------------------------------------------------------
# Schema checks
# ---------------------------------------------------------------------------


def check_additional_properties(
    tool_name: str, schema: dict, path: str
) -> list[Finding]:
    """
    HIGH: schemas without additionalProperties: false accept unexpected keys.
    This can allow attackers to inject undocumented parameters that bypass
    validation logic or confuse downstream processing.
    """
    if schema.get("additionalProperties") is not False:
        return [Finding(
            check_id="NO_ADDITIONAL_PROPERTIES_FALSE",
            severity="HIGH",
            tool_name=tool_name,
            field_path=path,
            message=f"Schema at {path!r} is missing 'additionalProperties: false'",
            detail=(
                "Without 'additionalProperties: false', any unexpected field will "
                "be silently accepted. This can mask injection attempts and makes "
                "the tool's contract ambiguous to both the AI model and validators."
            ),
        )]
    return []


def check_string_max_length(
    tool_name: str, properties: dict, required: list[str], path: str
) -> list[Finding]:
    """
    MEDIUM: string fields without maxLength can receive arbitrarily large
    inputs, which may exhaust memory, CPU, or downstream API quotas.
    """
    findings = []
    for field_name, field_schema in properties.items():
        if not isinstance(field_schema, dict):
            continue
        field_type = field_schema.get("type")
        is_string = field_type == "string" or (
            isinstance(field_type, list) and "string" in field_type
        )
        if is_string and "maxLength" not in field_schema:
            findings.append(Finding(
                check_id="STRING_MISSING_MAX_LENGTH",
                severity="MEDIUM",
                tool_name=tool_name,
                field_path=f"{path}.{field_name}",
                message=f"String field {field_name!r} has no 'maxLength' constraint",
                detail=(
                    f"Field '{field_name}' accepts strings of unlimited length. "
                    "Set 'maxLength' to prevent DoS via oversized inputs and to "
                    "signal intent clearly to the AI model."
                ),
            ))
    return findings


def check_required_array(
    tool_name: str, schema: dict, path: str
) -> list[Finding]:
    """
    MEDIUM: a schema without a 'required' array makes every field optional.
    This can allow callers to omit critical parameters, leading to unexpected
    behaviour or errors deep in the implementation.
    """
    findings = []
    properties = schema.get("properties", {})
    # Only flag if there are properties to require
    if properties and "required" not in schema:
        findings.append(Finding(
            check_id="NO_REQUIRED_ARRAY",
            severity="MEDIUM",
            tool_name=tool_name,
            field_path=path,
            message=f"Schema at {path!r} has no 'required' array — all fields are optional",
            detail=(
                "Without a 'required' array, the AI model can omit any field. "
                "Explicitly declare which fields must be present to enforce "
                "correct call structure and simplify implementation validation."
            ),
        ))
    return findings


def check_object_missing_properties(
    tool_name: str, schema: dict, path: str
) -> list[Finding]:
    """
    HIGH: a schema typed as 'object' but lacking a 'properties' definition
    is maximally permissive — it accepts any structure whatsoever.
    """
    findings = []
    schema_type = schema.get("type")
    is_object = schema_type == "object" or (
        isinstance(schema_type, list) and "object" in schema_type
    )
    if is_object and "properties" not in schema:
        findings.append(Finding(
            check_id="OBJECT_MISSING_PROPERTIES",
            severity="HIGH",
            tool_name=tool_name,
            field_path=path,
            message=f"Object schema at {path!r} has no 'properties' definition",
            detail=(
                "An object schema without 'properties' accepts any JSON object. "
                "This gives the AI model no guidance on what to send and prevents "
                "meaningful input validation. Define explicit properties."
            ),
        ))
    return findings


def check_untyped_fields(
    tool_name: str, properties: dict, path: str
) -> list[Finding]:
    """
    HIGH: fields without a 'type' or that use the informal 'any' type
    cannot be validated by schema-aware tools, and grant the AI model
    maximum freedom to send arbitrary data.
    """
    findings = []
    for field_name, field_schema in properties.items():
        if not isinstance(field_schema, dict):
            continue
        field_type = field_schema.get("type")

        if field_type is None:
            findings.append(Finding(
                check_id="MISSING_TYPE",
                severity="HIGH",
                tool_name=tool_name,
                field_path=f"{path}.{field_name}",
                message=f"Field {field_name!r} has no 'type' specified",
                detail=(
                    f"Omitting 'type' from field '{field_name}' means any JSON "
                    "value (string, number, object, array, null) is accepted. "
                    "Specify an explicit type to enable input validation."
                ),
            ))
        elif field_type == "any":
            findings.append(Finding(
                check_id="TYPE_ANY",
                severity="HIGH",
                tool_name=tool_name,
                field_path=f"{path}.{field_name}",
                message=f"Field {field_name!r} uses non-standard type 'any'",
                detail=(
                    f"'type: any' is not a valid JSON Schema type. It will be "
                    "ignored by validators, leaving the field unconstrained. "
                    "Use a specific JSON Schema type instead."
                ),
            ))
    return findings


def check_numeric_bounds(
    tool_name: str, properties: dict, path: str
) -> list[Finding]:
    """
    LOW: numeric fields without minimum/maximum constraints allow arbitrarily
    large or small values, which can trigger integer overflows, resource
    exhaustion, or unexpected branching in the implementation.
    """
    findings = []
    for field_name, field_schema in properties.items():
        if not isinstance(field_schema, dict):
            continue
        field_type = field_schema.get("type")
        types = {field_type} if isinstance(field_type, str) else set(field_type or [])
        if types & NUMERIC_TYPES:
            missing = []
            if "minimum" not in field_schema and "exclusiveMinimum" not in field_schema:
                missing.append("minimum")
            if "maximum" not in field_schema and "exclusiveMaximum" not in field_schema:
                missing.append("maximum")
            if missing:
                findings.append(Finding(
                    check_id="NUMERIC_NO_BOUNDS",
                    severity="LOW",
                    tool_name=tool_name,
                    field_path=f"{path}.{field_name}",
                    message=(
                        f"Numeric field {field_name!r} is missing: "
                        f"{', '.join(missing)}"
                    ),
                    detail=(
                        f"Without bounds on '{field_name}', the AI model can "
                        "supply arbitrarily large or small numbers. Add "
                        "'minimum' and 'maximum' constraints appropriate to the "
                        "expected value range."
                    ),
                ))
    return findings


def check_description_missing(
    tool_name: str, properties: dict, path: str
) -> list[Finding]:
    """
    LOW: properties without a 'description' leave the AI model without
    semantic guidance, increasing the likelihood of misuse or malformed calls.
    """
    findings = []
    for field_name, field_schema in properties.items():
        if not isinstance(field_schema, dict):
            continue
        if not field_schema.get("description"):
            findings.append(Finding(
                check_id="MISSING_DESCRIPTION",
                severity="LOW",
                tool_name=tool_name,
                field_path=f"{path}.{field_name}",
                message=f"Field {field_name!r} has no 'description'",
                detail=(
                    f"Without a description, the AI model must infer the purpose "
                    f"of '{field_name}' from its name alone, increasing the risk "
                    "of misuse. Add a concise description explaining the expected "
                    "value, units, and constraints."
                ),
            ))
    return findings


def check_empty_min_length_on_required(
    tool_name: str,
    properties: dict,
    required: list[str],
    path: str,
) -> list[Finding]:
    """
    LOW: a required string field with minLength: 0 allows empty strings,
    which typically indicate a missing or malformed value and can cause
    downstream errors.
    """
    findings = []
    for field_name in required:
        field_schema = properties.get(field_name)
        if not isinstance(field_schema, dict):
            continue
        field_type = field_schema.get("type")
        is_string = field_type == "string" or (
            isinstance(field_type, list) and "string" in field_type
        )
        if is_string and field_schema.get("minLength") == 0:
            findings.append(Finding(
                check_id="REQUIRED_STRING_ALLOWS_EMPTY",
                severity="LOW",
                tool_name=tool_name,
                field_path=f"{path}.{field_name}",
                message=(
                    f"Required string field {field_name!r} allows empty strings "
                    f"(minLength: 0)"
                ),
                detail=(
                    f"Field '{field_name}' is required but permits an empty "
                    "string. An empty value is functionally equivalent to "
                    "missing the field. Set 'minLength' to at least 1."
                ),
            ))
    return findings


# ---------------------------------------------------------------------------
# Schema validator orchestration
# ---------------------------------------------------------------------------


def validate_tool_schema(tool_name: str, input_schema: dict) -> list[Finding]:
    """
    Run all checks against a single tool's inputSchema.
    Recursively checks nested object schemas within properties.
    """
    findings: list[Finding] = []
    root_path = "inputSchema"

    # Top-level schema checks
    findings.extend(check_additional_properties(tool_name, input_schema, root_path))
    findings.extend(check_object_missing_properties(tool_name, input_schema, root_path))
    findings.extend(check_required_array(tool_name, input_schema, root_path))

    properties: dict = input_schema.get("properties") or {}
    required: list[str] = input_schema.get("required") or []

    if isinstance(properties, dict) and properties:
        findings.extend(check_string_max_length(tool_name, properties, required, root_path + ".properties"))
        findings.extend(check_untyped_fields(tool_name, properties, root_path + ".properties"))
        findings.extend(check_numeric_bounds(tool_name, properties, root_path + ".properties"))
        findings.extend(check_description_missing(tool_name, properties, root_path + ".properties"))
        findings.extend(check_empty_min_length_on_required(tool_name, properties, required, root_path + ".properties"))

        # Recursively validate nested object schemas
        for field_name, field_schema in properties.items():
            if not isinstance(field_schema, dict):
                continue
            field_type = field_schema.get("type")
            is_object = field_type == "object" or (
                isinstance(field_type, list) and "object" in field_type
            )
            if is_object:
                nested_path = f"{root_path}.properties.{field_name}"
                findings.extend(check_additional_properties(tool_name, field_schema, nested_path))
                findings.extend(check_object_missing_properties(tool_name, field_schema, nested_path))

                nested_props = field_schema.get("properties") or {}
                if isinstance(nested_props, dict) and nested_props:
                    nested_required = field_schema.get("required") or []
                    sub_path = nested_path + ".properties"
                    findings.extend(check_string_max_length(tool_name, nested_props, nested_required, sub_path))
                    findings.extend(check_untyped_fields(tool_name, nested_props, sub_path))
                    findings.extend(check_numeric_bounds(tool_name, nested_props, sub_path))
                    findings.extend(check_description_missing(tool_name, nested_props, sub_path))
                    findings.extend(check_empty_min_length_on_required(tool_name, nested_props, nested_required, sub_path))

    return findings


def validate_all(tools: list[dict]) -> list[Finding]:
    """
    Validate a list of tool objects and return all findings, sorted by severity.
    """
    findings: list[Finding] = []

    for idx, tool in enumerate(tools):
        if not isinstance(tool, dict):
            findings.append(Finding(
                check_id="INVALID_TOOL_ENTRY",
                severity="HIGH",
                tool_name=None,
                field_path=f"[{idx}]",
                message=f"Tool entry at index {idx} is not an object",
                detail="Each tool must be a JSON object with 'name' and 'inputSchema' keys.",
            ))
            continue

        tool_name: str = tool.get("name") or f"<unnamed:{idx}>"
        input_schema = tool.get("inputSchema")

        if not isinstance(input_schema, dict):
            findings.append(Finding(
                check_id="MISSING_INPUT_SCHEMA",
                severity="HIGH",
                tool_name=tool_name,
                field_path="inputSchema",
                message=f"Tool {tool_name!r} is missing a valid 'inputSchema'",
                detail=(
                    "Every MCP tool must declare an 'inputSchema' JSON Schema "
                    "object so that inputs can be validated before reaching "
                    "tool implementation code."
                ),
            ))
            continue

        findings.extend(validate_tool_schema(tool_name, input_schema))

    # Sort: HIGH → MEDIUM → LOW; stable within each group
    severity_rank = {s: i for i, s in enumerate(SEVERITY_ORDER)}
    findings.sort(key=lambda f: severity_rank.get(f.severity, 99))

    return findings


# ---------------------------------------------------------------------------
# Output formatting
# ---------------------------------------------------------------------------


def _colour(text: str, code: str, use_colour: bool) -> str:
    if not use_colour:
        return text
    return f"{code}{text}{COLOURS['RESET']}"


def _severity_badge(severity: str, use_colour: bool) -> str:
    colour_map = {
        "HIGH":   COLOURS["HIGH"],
        "MEDIUM": COLOURS["MEDIUM"],
        "LOW":    COLOURS["LOW"],
    }
    code = colour_map.get(severity, "")
    label = f"[{severity}]"
    return _colour(label, COLOURS["BOLD"] + code, use_colour)


def print_human_report(findings: list[Finding], source_label: str, use_colour: bool) -> None:
    bold  = COLOURS["BOLD"]  if use_colour else ""
    dim   = COLOURS["DIM"]   if use_colour else ""
    green = COLOURS["GREEN"] if use_colour else ""
    reset = COLOURS["RESET"] if use_colour else ""

    print(f"\n{bold}MCP Tool Schema Security Validator{reset}")
    print(f"{dim}Source: {source_label}{reset}")
    print()

    if not findings:
        print(f"{green}No findings — schema looks well-formed.{reset}\n")
        return

    for finding in findings:
        badge = _severity_badge(finding.severity, use_colour)
        tool_label  = f"[{finding.tool_name}] "  if finding.tool_name  else ""
        field_label = f"({finding.field_path}) "  if finding.field_path else ""
        print(f"  {badge} {bold}{tool_label}{reset}{dim}{field_label}{reset}{finding.message}")
        if finding.detail:
            for line in _wrap(finding.detail, width=76, indent="         "):
                print(line)
        print()

    high   = sum(1 for f in findings if f.severity == "HIGH")
    medium = sum(1 for f in findings if f.severity == "MEDIUM")
    low    = sum(1 for f in findings if f.severity == "LOW")
    total  = len(findings)

    high_str   = _colour(f"{high} high",     COLOURS["HIGH"],   use_colour)
    medium_str = _colour(f"{medium} medium",  COLOURS["MEDIUM"], use_colour)
    low_str    = _colour(f"{low} low",        COLOURS["LOW"],    use_colour)

    print(f"{bold}Summary:{reset} {total} finding{'s' if total != 1 else ''} "
          f"({high_str}, {medium_str}, {low_str})\n")


def print_json_report(findings: list[Finding], source_label: str) -> None:
    high   = sum(1 for f in findings if f.severity == "HIGH")
    medium = sum(1 for f in findings if f.severity == "MEDIUM")
    low    = sum(1 for f in findings if f.severity == "LOW")

    report = {
        "tool": "validate-schema",
        "version": TOOL_VERSION,
        "source": source_label,
        "summary": {
            "total": len(findings),
            "high": high,
            "medium": medium,
            "low": low,
        },
        "findings": [f.to_dict() for f in findings],
    }
    print(json.dumps(report, indent=2))


def _wrap(text: str, width: int, indent: str) -> list[str]:
    """Simple word-wrapper that respects the given indent string."""
    words = text.split()
    lines = []
    current = indent
    for word in words:
        if current == indent:
            current += word
        elif len(current) + 1 + len(word) <= width + len(indent):
            current += " " + word
        else:
            lines.append(current)
            current = indent + word
    if current != indent:
        lines.append(current)
    return lines


# ---------------------------------------------------------------------------
# CLI entry point
# ---------------------------------------------------------------------------


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        prog="validate-schema",
        description="Validate MCP tool schemas against security best practices.",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=(
            "Examples:\n"
            "  %(prog)s tool-schema.json\n"
            "  %(prog)s --json tool-schema.json\n"
        ),
    )
    parser.add_argument(
        "schema",
        metavar="SCHEMA",
        help="Path to a JSON file containing one tool object or an array of tool objects.",
    )
    parser.add_argument(
        "--json",
        action="store_true",
        dest="output_json",
        help="Output machine-readable JSON instead of coloured text.",
    )
    parser.add_argument(
        "--no-colour",
        "--no-color",
        action="store_true",
        dest="no_colour",
        help="Disable ANSI colour output even when writing to a terminal.",
    )
    parser.add_argument(
        "--version",
        action="version",
        version=f"%(prog)s {TOOL_VERSION}",
    )
    return parser.parse_args()


def main() -> int:
    args = parse_args()

    # Determine whether to emit ANSI colours
    use_colour = (
        not args.output_json
        and not args.no_colour
        and sys.stdout.isatty()
        and os.environ.get("NO_COLOR") is None
        and os.environ.get("TERM") != "dumb"
    )

    # ---------------------------------------------------------------------------
    # Read input
    # ---------------------------------------------------------------------------

    source_label = args.schema
    if not os.path.exists(args.schema):
        print(f"Error: file not found: {args.schema!r}", file=sys.stderr)
        return 2

    try:
        with open(args.schema, "r", encoding="utf-8") as fh:
            raw = fh.read()
    except OSError as exc:
        print(f"Error: cannot read {args.schema!r}: {exc}", file=sys.stderr)
        return 2

    # ---------------------------------------------------------------------------
    # Parse JSON
    # ---------------------------------------------------------------------------

    try:
        data = json.loads(raw)
    except json.JSONDecodeError as exc:
        print(f"Error: invalid JSON in {source_label}: {exc}", file=sys.stderr)
        return 2

    # Normalise: accept a single object or an array of objects
    if isinstance(data, dict):
        tools = [data]
    elif isinstance(data, list):
        tools = data
    else:
        print(
            f"Error: expected a JSON object or array, got {type(data).__name__}",
            file=sys.stderr,
        )
        return 2

    # ---------------------------------------------------------------------------
    # Validate
    # ---------------------------------------------------------------------------

    findings = validate_all(tools)

    # ---------------------------------------------------------------------------
    # Output
    # ---------------------------------------------------------------------------

    if args.output_json:
        print_json_report(findings, source_label)
    else:
        print_human_report(findings, source_label, use_colour)

    has_high = any(f.severity == "HIGH" for f in findings)
    return 1 if has_high else 0


if __name__ == "__main__":
    sys.exit(main())
