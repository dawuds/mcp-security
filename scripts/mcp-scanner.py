#!/usr/bin/env python3
"""
mcp-scanner.py — MCP Server Configuration Security Auditor

Audits an MCP server configuration file (e.g. Claude Desktop's
claude_desktop_config.json) for common security misconfigurations.

Expected config structure:
    {
        "mcpServers": {
            "server-name": {
                "command": "npx",
                "args": ["-y", "@modelcontextprotocol/server-filesystem", "/tmp"],
                "env": {"MY_VAR": "value"}
            }
        }
    }

Usage:
    python mcp-scanner.py config.json
    python mcp-scanner.py -           # read from stdin
    python mcp-scanner.py --json config.json

Exit codes:
    0 — no HIGH severity findings
    1 — one or more HIGH severity findings
"""

import argparse
import json
import os
import re
import sys
from typing import Any

# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------

TOOL_VERSION = "0.1.0"

# Severity levels and their display order (highest first)
SEVERITY_ORDER = ["HIGH", "MEDIUM", "LOW"]

# ANSI colour codes — disabled automatically when not writing to a terminal
COLOURS = {
    "HIGH":   "\033[91m",  # Bright red
    "MEDIUM": "\033[93m",  # Bright yellow
    "LOW":    "\033[94m",  # Bright blue
    "RESET":  "\033[0m",
    "BOLD":   "\033[1m",
    "DIM":    "\033[2m",
    "GREEN":  "\033[92m",
}

# Shell interpreters that should not be used as MCP commands directly
SHELL_COMMANDS = {"bash", "sh", "zsh", "fish", "dash", "ksh", "cmd", "cmd.exe", "powershell", "pwsh"}

# Env-var key patterns that likely contain sensitive material (case-insensitive)
SENSITIVE_ENV_PATTERNS = re.compile(
    r"(SECRET|PASSWORD|PASSWD|TOKEN|API_KEY|APIKEY|CREDENTIAL|CREDENTIALS|PRIVATE_KEY|ACCESS_KEY)",
    re.IGNORECASE,
)

# Shell metacharacters inside args that suggest injection risk
SHELL_METACHAR_PATTERN = re.compile(r"(\|+|;|&&|\|\||`|\$\()")

# Maximum number of MCP servers before we warn about attack surface size
MAX_SERVERS_THRESHOLD = 20

# ---------------------------------------------------------------------------
# Data model
# ---------------------------------------------------------------------------


class Finding:
    """A single security finding against a config element."""

    def __init__(
        self,
        check_id: str,
        severity: str,
        server_name: str | None,
        message: str,
        detail: str | None = None,
    ) -> None:
        self.check_id = check_id
        self.severity = severity
        self.server_name = server_name
        self.message = message
        self.detail = detail

    def to_dict(self) -> dict[str, Any]:
        d: dict[str, Any] = {
            "check_id": self.check_id,
            "severity": self.severity,
            "server": self.server_name,
            "message": self.message,
        }
        if self.detail:
            d["detail"] = self.detail
        return d


# ---------------------------------------------------------------------------
# Individual security checks
# ---------------------------------------------------------------------------


def check_transport_security(name: str, config: dict) -> list[Finding]:
    """
    Warn if the server is configured to use plain HTTP rather than HTTPS or
    stdio. stdio transport is always acceptable; HTTP without TLS is not.
    """
    findings = []
    command = config.get("command", "")
    args = config.get("args", [])

    # Look for explicit http:// URLs in command or args
    all_strings = [command] + [a for a in args if isinstance(a, str)]
    for value in all_strings:
        if re.search(r"\bhttp://", value, re.IGNORECASE):
            findings.append(Finding(
                check_id="TRANSPORT_NO_TLS",
                severity="HIGH",
                server_name=name,
                message="Server uses plain HTTP without TLS",
                detail=(
                    f"Value {value!r} contains an http:// URL. "
                    "Use https:// or stdio transport to protect data in transit."
                ),
            ))
            break  # One finding per server is enough

    return findings


def check_sensitive_env_vars(name: str, config: dict) -> list[Finding]:
    """
    Flag environment variable keys that appear to hold secrets (tokens,
    passwords, API keys, etc.). Exposing these in a config file on disk
    is a credential-leakage risk.
    """
    findings = []
    env = config.get("env")
    if not isinstance(env, dict):
        return findings

    flagged_keys = [k for k in env if SENSITIVE_ENV_PATTERNS.search(str(k))]
    if flagged_keys:
        findings.append(Finding(
            check_id="SENSITIVE_ENV_VAR",
            severity="HIGH",
            server_name=name,
            message="Sensitive credentials detected in env block",
            detail=(
                f"Potentially sensitive env keys: {', '.join(flagged_keys)}. "
                "Prefer injecting secrets at runtime via a secrets manager or "
                "environment variable inheritance rather than hardcoding them "
                "in the config file."
            ),
        ))
    return findings


def check_shell_command(name: str, config: dict) -> list[Finding]:
    """
    Flag if the MCP server command is a shell interpreter. Invoking a shell
    as the MCP command dramatically expands the attack surface — a shell
    can run arbitrary sub-commands. Prefer direct execution of the target
    binary.
    """
    findings = []
    command = config.get("command", "")
    if not isinstance(command, str):
        return findings

    # Normalise: strip path prefix and any .exe suffix for comparison
    bare_command = os.path.basename(command).lower().removesuffix(".exe")
    if bare_command in SHELL_COMMANDS:
        findings.append(Finding(
            check_id="SHELL_COMMAND",
            severity="HIGH",
            server_name=name,
            message=f"Command is a shell interpreter: {command!r}",
            detail=(
                "Invoking a shell as the MCP command allows arbitrary command "
                "execution. Specify the target binary directly instead."
            ),
        ))
    return findings


def check_missing_env_isolation(name: str, config: dict) -> list[Finding]:
    """
    Note when no env block is present. Without an explicit env block the
    child process inherits the full parent environment, which may contain
    credentials or sensitive configuration values the MCP server does not need.
    """
    findings = []
    if "env" not in config:
        findings.append(Finding(
            check_id="NO_ENV_ISOLATION",
            severity="LOW",
            server_name=name,
            message="No env block — process inherits parent environment",
            detail=(
                "Without an explicit 'env' key the MCP server process inherits "
                "all environment variables from the parent (e.g. Claude Desktop). "
                "Add an 'env' block to limit which variables are passed through."
            ),
        ))
    return findings


def check_suspicious_args(name: str, config: dict) -> list[Finding]:
    """
    Flag args that contain shell metacharacters. These can enable command
    injection if the MCP launcher eventually passes args through a shell.
    """
    findings = []
    args = config.get("args", [])
    if not isinstance(args, list):
        return findings

    for arg in args:
        if not isinstance(arg, str):
            continue
        match = SHELL_METACHAR_PATTERN.search(arg)
        if match:
            findings.append(Finding(
                check_id="SUSPICIOUS_ARG",
                severity="MEDIUM",
                server_name=name,
                message=f"Arg contains shell metacharacter {match.group()!r}",
                detail=(
                    f"Argument value: {arg!r}. Shell metacharacters can enable "
                    "command injection if args are later interpreted by a shell."
                ),
            ))
    return findings


def check_too_many_servers(names: list[str]) -> list[Finding]:
    """
    Warn when the number of configured MCP servers exceeds the threshold.
    Each server is a potential attack surface; unnecessary servers should
    be removed.
    """
    findings = []
    count = len(names)
    if count > MAX_SERVERS_THRESHOLD:
        findings.append(Finding(
            check_id="TOO_MANY_SERVERS",
            severity="MEDIUM",
            server_name=None,
            message=f"{count} MCP servers configured (threshold: {MAX_SERVERS_THRESHOLD})",
            detail=(
                "A large number of MCP servers increases the attack surface. "
                "Remove servers that are not actively needed."
            ),
        ))
    return findings


def check_duplicate_server_names(names: list[str]) -> list[Finding]:
    """
    Flag duplicate server names. If two entries share a name, one may
    silently shadow the other depending on parsing order, causing
    unexpected tool routing.
    """
    findings = []
    seen: dict[str, int] = {}
    for n in names:
        seen[n] = seen.get(n, 0) + 1

    duplicates = [n for n, count in seen.items() if count > 1]
    if duplicates:
        findings.append(Finding(
            check_id="DUPLICATE_SERVER_NAME",
            severity="MEDIUM",
            server_name=None,
            message=f"Duplicate server name(s): {', '.join(duplicates)}",
            detail=(
                "Duplicate names can cause one server entry to shadow another, "
                "leading to unexpected tool routing or privilege confusion."
            ),
        ))
    return findings


def check_empty_server_entry(name: str, config: dict) -> list[Finding]:
    """
    Flag servers with an empty name or missing/empty command. These are
    likely misconfigured entries that may behave unpredictably.
    """
    findings = []

    if not name or not name.strip():
        findings.append(Finding(
            check_id="EMPTY_SERVER_NAME",
            severity="MEDIUM",
            server_name=repr(name),
            message="Server has an empty or blank name",
            detail="Server entries must have a meaningful name for identification and audit purposes.",
        ))

    command = config.get("command", "")
    if not command or not str(command).strip():
        findings.append(Finding(
            check_id="EMPTY_SERVER_COMMAND",
            severity="MEDIUM",
            server_name=name or repr(name),
            message="Server has no command specified",
            detail=(
                "A missing or empty 'command' field means the MCP launcher "
                "has no process to start. This entry is likely a misconfiguration."
            ),
        ))

    return findings


# ---------------------------------------------------------------------------
# Scanner orchestration
# ---------------------------------------------------------------------------


# Per-server checks: each takes (server_name: str, server_config: dict)
PER_SERVER_CHECKS = [
    check_transport_security,
    check_sensitive_env_vars,
    check_shell_command,
    check_missing_env_isolation,
    check_suspicious_args,
    check_empty_server_entry,
]


def audit_config(config: dict) -> list[Finding]:
    """
    Run all checks against a parsed MCP config dict.
    Returns a flat list of Finding objects sorted by severity.
    """
    findings: list[Finding] = []

    servers: dict = config.get("mcpServers", {})
    if not isinstance(servers, dict):
        findings.append(Finding(
            check_id="INVALID_CONFIG",
            severity="HIGH",
            server_name=None,
            message="'mcpServers' is not an object — config is malformed",
            detail="The top-level 'mcpServers' key must be a JSON object mapping names to server configs.",
        ))
        return findings

    server_names = list(servers.keys())

    # Global checks (operate on the full server list)
    findings.extend(check_too_many_servers(server_names))
    findings.extend(check_duplicate_server_names(server_names))

    # Per-server checks
    for name, server_config in servers.items():
        if not isinstance(server_config, dict):
            findings.append(Finding(
                check_id="INVALID_SERVER_CONFIG",
                severity="MEDIUM",
                server_name=name,
                message="Server config is not an object",
                detail=f"Expected a JSON object for server {name!r}, got {type(server_config).__name__}.",
            ))
            continue

        for check_fn in PER_SERVER_CHECKS:
            findings.extend(check_fn(name, server_config))

    # Sort: HIGH first, then MEDIUM, then LOW; stable within each group
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
    """Print a human-readable report to stdout."""
    bold = COLOURS["BOLD"] if use_colour else ""
    dim = COLOURS["DIM"] if use_colour else ""
    green = COLOURS["GREEN"] if use_colour else ""
    reset = COLOURS["RESET"] if use_colour else ""

    print(f"\n{bold}MCP Config Security Audit{reset}")
    print(f"{dim}Source: {source_label}{reset}")
    print()

    if not findings:
        print(f"{green}No findings — configuration looks clean.{reset}\n")
        return

    for finding in findings:
        badge = _severity_badge(finding.severity, use_colour)
        server_label = f"[{finding.server_name}] " if finding.server_name else ""
        print(f"  {badge} {bold}{server_label}{finding.message}{reset}")
        if finding.detail:
            # Word-wrap detail lines at 80 chars with indentation
            for line in _wrap(finding.detail, width=76, indent="         "):
                print(line)
        print()

    # Summary counts
    high   = sum(1 for f in findings if f.severity == "HIGH")
    medium = sum(1 for f in findings if f.severity == "MEDIUM")
    low    = sum(1 for f in findings if f.severity == "LOW")
    total  = len(findings)

    high_str   = _colour(f"{high} high",   COLOURS["HIGH"],   use_colour)
    medium_str = _colour(f"{medium} medium", COLOURS["MEDIUM"], use_colour)
    low_str    = _colour(f"{low} low",     COLOURS["LOW"],    use_colour)

    print(f"{bold}Summary:{reset} {total} finding{'s' if total != 1 else ''} "
          f"({high_str}, {medium_str}, {low_str})\n")


def print_json_report(findings: list[Finding], source_label: str) -> None:
    """Print a machine-readable JSON report to stdout."""
    high   = sum(1 for f in findings if f.severity == "HIGH")
    medium = sum(1 for f in findings if f.severity == "MEDIUM")
    low    = sum(1 for f in findings if f.severity == "LOW")

    report = {
        "tool": "mcp-scanner",
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
        prog="mcp-scanner",
        description="Audit an MCP server configuration file for security misconfigurations.",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=(
            "Examples:\n"
            "  %(prog)s claude_desktop_config.json\n"
            "  %(prog)s --json claude_desktop_config.json\n"
            "  cat config.json | %(prog)s -\n"
        ),
    )
    parser.add_argument(
        "config",
        metavar="CONFIG",
        help="Path to the MCP config JSON file, or '-' to read from stdin.",
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

    # Determine whether to use ANSI colours
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

    if args.config == "-":
        source_label = "<stdin>"
        raw = sys.stdin.read()
    else:
        source_label = args.config
        if not os.path.exists(args.config):
            print(f"Error: file not found: {args.config!r}", file=sys.stderr)
            return 2
        try:
            with open(args.config, "r", encoding="utf-8") as fh:
                raw = fh.read()
        except OSError as exc:
            print(f"Error: cannot read {args.config!r}: {exc}", file=sys.stderr)
            return 2

    # ---------------------------------------------------------------------------
    # Parse JSON
    # ---------------------------------------------------------------------------

    try:
        config = json.loads(raw)
    except json.JSONDecodeError as exc:
        print(f"Error: invalid JSON in {source_label}: {exc}", file=sys.stderr)
        return 2

    if not isinstance(config, dict):
        print(
            f"Error: expected a JSON object at top level, got {type(config).__name__}",
            file=sys.stderr,
        )
        return 2

    # ---------------------------------------------------------------------------
    # Run audit
    # ---------------------------------------------------------------------------

    findings = audit_config(config)

    # ---------------------------------------------------------------------------
    # Output
    # ---------------------------------------------------------------------------

    if args.output_json:
        print_json_report(findings, source_label)
    else:
        print_human_report(findings, source_label, use_colour)

    # Exit 1 if any HIGH findings, 0 otherwise
    has_high = any(f.severity == "HIGH" for f in findings)
    return 1 if has_high else 0


if __name__ == "__main__":
    sys.exit(main())
