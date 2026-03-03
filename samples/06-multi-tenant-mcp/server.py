"""
Sample 06: Multi-Tenant MCP Server

Demonstrates tenant isolation in a shared MCP server. A single server
instance serves multiple tenants; data and operations are strictly
namespaced by tenant ID so no tenant can read or affect another's data.

Key security controls:
- Tenant namespacing: every stored key is prefixed with
  "tenant:{tenant_id}:" — cross-tenant key collisions are structurally
  impossible and never manually enforced at call time.
- Tenant ID validation: tenant ID must match ^[a-zA-Z0-9_-]{1,64}$;
  invalid IDs are rejected at startup and on every tool call.
- Cross-tenant prevention: operations only ever touch keys that start
  with the current tenant's prefix; access-denied responses do not
  reveal whether another tenant's key exists.
- Tenant-scoped audit logging: every log entry includes tenant_id.
- Resource quotas: each tenant is limited to MCP_TENANT_QUOTA stored
  key-value pairs (default 50); set_value enforces this before writing.
- No tenant enumeration: error messages are generic — "key not found"
  rather than "that key belongs to another tenant".
"""

import json
import logging
import os
import re
import sys
import time
import uuid
from typing import Any

from mcp.server import Server
from mcp.server.stdio import stdio_server
from mcp.types import (
    CallToolRequest,
    CallToolResult,
    ListToolsRequest,
    ListToolsResult,
    TextContent,
    Tool,
)

# ---------------------------------------------------------------------------
# Logging setup
# ---------------------------------------------------------------------------

logging.basicConfig(
    stream=sys.stderr,
    level=logging.INFO,
    format="%(message)s",  # We'll emit structured JSON
)
audit_log = logging.getLogger("mcp.audit")
app_log = logging.getLogger("mcp.app")

# ---------------------------------------------------------------------------
# Configuration
# ---------------------------------------------------------------------------

SERVER_NAME = "multi-tenant-mcp"
SERVER_VERSION = "0.1.0"

# In production this tenant ID would be derived from the authenticated
# session (e.g. a verified JWT sub claim or an SSO identity).  Here we
# read it from an environment variable to keep the demo self-contained.
_RAW_TENANT_ID = os.environ.get("MCP_TENANT_ID", "")

# Max key-value pairs stored per tenant.
TENANT_QUOTA = int(os.environ.get("MCP_TENANT_QUOTA", "50"))

# Regex patterns
_TENANT_ID_RE = re.compile(r"^[a-zA-Z0-9_-]{1,64}$")
_KEY_RE = re.compile(r"^[a-zA-Z0-9_.\-]{1,128}$")

MAX_VALUE_LENGTH = 10_000

# ---------------------------------------------------------------------------
# In-memory "database"
# ---------------------------------------------------------------------------
# NOTE: This is a demo-only in-memory store.  In production use a real
# database with row-level security so that the isolation guarantee is
# enforced at the storage layer, not just in application code.
_store: dict[str, str] = {}


# ---------------------------------------------------------------------------
# Tenant ID helpers
# ---------------------------------------------------------------------------


def validate_tenant_id(tenant_id: str) -> str:
    """Return the tenant ID if valid, raise ValueError otherwise."""
    if not isinstance(tenant_id, str) or not _TENANT_ID_RE.match(tenant_id):
        raise ValueError(
            "Tenant ID must be 1-64 characters: letters, digits, underscores, hyphens"
        )
    return tenant_id


def _tenant_prefix(tenant_id: str) -> str:
    """Return the storage prefix for this tenant."""
    return f"tenant:{tenant_id}:"


def _make_store_key(tenant_id: str, user_key: str) -> str:
    """Build the fully-qualified (namespaced) storage key."""
    return f"{_tenant_prefix(tenant_id)}{user_key}"


def _get_current_tenant() -> str:
    """
    Return the validated tenant ID for the current request.

    In production this would be derived from the authenticated session
    rather than an environment variable.
    """
    return validate_tenant_id(_RAW_TENANT_ID)


# ---------------------------------------------------------------------------
# Audit logging
# ---------------------------------------------------------------------------


def log_tool_call(
    call_id: str,
    tool_name: str,
    tenant_id: str,
    input_summary: dict,
    outcome: str,
    duration_ms: int,
    error_type: str | None = None,
) -> None:
    """Emit a structured audit log entry for a tool call."""
    entry = {
        "timestamp": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
        "call_id": call_id,
        "server": SERVER_NAME,
        "tenant_id": tenant_id,  # Always present for tenant-scoped audit trail
        "tool": tool_name,
        "input_summary": input_summary,
        "outcome": outcome,
        "duration_ms": duration_ms,
    }
    if error_type:
        entry["error_type"] = error_type
    audit_log.info(json.dumps(entry))


# ---------------------------------------------------------------------------
# Input validation
# ---------------------------------------------------------------------------


def validate_user_key(key: str) -> str:
    """Return key if valid, raise ValueError otherwise."""
    if not isinstance(key, str) or not _KEY_RE.match(key):
        raise ValueError(
            "Key must be 1-128 characters: letters, digits, underscores, dots, hyphens"
        )
    return key


def validate_value(value: Any) -> str:
    """Return value if it is a valid string, raise ValueError otherwise."""
    if not isinstance(value, str):
        raise ValueError("'value' must be a string")
    if len(value) > MAX_VALUE_LENGTH:
        raise ValueError(
            f"'value' exceeds maximum length of {MAX_VALUE_LENGTH} characters"
        )
    return value


# ---------------------------------------------------------------------------
# Tool schemas
# ---------------------------------------------------------------------------

SET_VALUE_SCHEMA: dict[str, Any] = {
    "type": "object",
    "properties": {
        "key": {
            "type": "string",
            "description": "Key to store the value under (namespaced to this tenant)",
            "minLength": 1,
            "maxLength": 128,
            "pattern": r"^[a-zA-Z0-9_.\-]{1,128}$",
        },
        "value": {
            "type": "string",
            "description": "Value to store",
            "maxLength": MAX_VALUE_LENGTH,
        },
    },
    "required": ["key", "value"],
    "additionalProperties": False,
}

GET_VALUE_SCHEMA: dict[str, Any] = {
    "type": "object",
    "properties": {
        "key": {
            "type": "string",
            "description": "Key to retrieve (namespaced to this tenant)",
            "minLength": 1,
            "maxLength": 128,
        },
    },
    "required": ["key"],
    "additionalProperties": False,
}

LIST_KEYS_SCHEMA: dict[str, Any] = {
    "type": "object",
    "properties": {},
    "additionalProperties": False,
}

DELETE_VALUE_SCHEMA: dict[str, Any] = {
    "type": "object",
    "properties": {
        "key": {
            "type": "string",
            "description": "Key to delete (namespaced to this tenant)",
            "minLength": 1,
            "maxLength": 128,
        },
    },
    "required": ["key"],
    "additionalProperties": False,
}

GET_QUOTA_SCHEMA: dict[str, Any] = {
    "type": "object",
    "properties": {},
    "additionalProperties": False,
}

# ---------------------------------------------------------------------------
# Tool implementations
# ---------------------------------------------------------------------------


def tool_set_value(arguments: dict, tenant_id: str) -> str:
    """Store a key-value pair for this tenant, enforcing quota."""
    raw_key = arguments.get("key")
    raw_value = arguments.get("value")

    if not isinstance(raw_key, str):
        raise ValueError("'key' must be a string")

    key = validate_user_key(raw_key)
    value = validate_value(raw_value)

    store_key = _make_store_key(tenant_id, key)
    prefix = _tenant_prefix(tenant_id)

    # Count how many keys this tenant already has (excluding the one being
    # written, which may be an update rather than a new entry).
    tenant_keys = [k for k in _store if k.startswith(prefix)]
    is_update = store_key in _store
    if not is_update and len(tenant_keys) >= TENANT_QUOTA:
        raise ValueError(
            f"Quota exceeded: this tenant has reached the limit of {TENANT_QUOTA} "
            "stored key-value pairs. Delete an existing key before adding a new one."
        )

    _store[store_key] = value
    return f"Stored key {key!r} successfully."


def tool_get_value(arguments: dict, tenant_id: str) -> str:
    """Retrieve a value by key for this tenant."""
    raw_key = arguments.get("key")

    if not isinstance(raw_key, str):
        raise ValueError("'key' must be a string")

    key = validate_user_key(raw_key)
    store_key = _make_store_key(tenant_id, key)

    # We never look outside this tenant's prefix.  If the key is absent
    # we return a generic "not found" — we do not reveal whether the key
    # exists under a different tenant's prefix.
    if store_key not in _store:
        raise ValueError(f"Key not found: {key!r}")

    return _store[store_key]


def tool_list_keys(arguments: dict, tenant_id: str) -> dict:
    """List all keys belonging to this tenant only."""
    prefix = _tenant_prefix(tenant_id)
    prefix_len = len(prefix)

    # Strip the internal prefix before returning keys to the caller so
    # that the namespacing implementation detail stays hidden.
    user_keys = sorted(
        k[prefix_len:] for k in _store if k.startswith(prefix)
    )
    return {"keys": user_keys, "count": len(user_keys)}


def tool_delete_value(arguments: dict, tenant_id: str) -> str:
    """Delete a key for this tenant."""
    raw_key = arguments.get("key")

    if not isinstance(raw_key, str):
        raise ValueError("'key' must be a string")

    key = validate_user_key(raw_key)
    store_key = _make_store_key(tenant_id, key)

    if store_key not in _store:
        raise ValueError(f"Key not found: {key!r}")

    del _store[store_key]
    return f"Deleted key {key!r} successfully."


def tool_get_quota(arguments: dict, tenant_id: str) -> dict:
    """Return quota usage for this tenant."""
    prefix = _tenant_prefix(tenant_id)
    used = sum(1 for k in _store if k.startswith(prefix))
    return {
        "tenant_id": tenant_id,
        "used": used,
        "limit": TENANT_QUOTA,
        "available": TENANT_QUOTA - used,
    }


# ---------------------------------------------------------------------------
# Server setup
# ---------------------------------------------------------------------------

TOOLS = [
    Tool(
        name="set_value",
        description=(
            "Store a key-value pair for this tenant. "
            "Keys and values are isolated from all other tenants."
        ),
        inputSchema=SET_VALUE_SCHEMA,
    ),
    Tool(
        name="get_value",
        description="Retrieve a stored value by key for this tenant.",
        inputSchema=GET_VALUE_SCHEMA,
    ),
    Tool(
        name="list_keys",
        description="List all keys stored for this tenant.",
        inputSchema=LIST_KEYS_SCHEMA,
    ),
    Tool(
        name="delete_value",
        description="Delete a stored key-value pair for this tenant.",
        inputSchema=DELETE_VALUE_SCHEMA,
    ),
    Tool(
        name="get_quota",
        description="Return this tenant's quota usage (used / limit).",
        inputSchema=GET_QUOTA_SCHEMA,
    ),
]

TOOL_HANDLERS = {
    "set_value": tool_set_value,
    "get_value": tool_get_value,
    "list_keys": tool_list_keys,
    "delete_value": tool_delete_value,
    "get_quota": tool_get_quota,
}

server = Server(SERVER_NAME)


@server.list_tools()
async def handle_list_tools(request: ListToolsRequest) -> ListToolsResult:
    return ListToolsResult(tools=TOOLS)


@server.call_tool()
async def handle_call_tool(request: CallToolRequest) -> CallToolResult:
    call_id = str(uuid.uuid4())
    tool_name = request.params.name
    arguments = request.params.arguments or {}
    start = time.monotonic()
    outcome = "success"
    error_type = None

    # Resolve the tenant ID for this call.  If the tenant ID is invalid
    # we reject the call immediately before doing any work.
    try:
        tenant_id = _get_current_tenant()
    except ValueError as exc:
        # Log with a placeholder tenant since we could not determine one.
        log_tool_call(
            call_id=call_id,
            tool_name=tool_name,
            tenant_id="<invalid>",
            input_summary={},
            outcome="error",
            duration_ms=0,
            error_type="InvalidTenant",
        )
        return CallToolResult(
            content=[TextContent(type="text", text=f"Error: {exc}")],
            isError=True,
        )

    # Sanitize arguments for logging — avoid logging sensitive values.
    input_summary = {
        k: (v[:100] + "..." if isinstance(v, str) and len(v) > 100 else v)
        for k, v in arguments.items()
        if k != "value"  # Never log stored values — they may be secrets.
    }

    try:
        handler = TOOL_HANDLERS.get(tool_name)
        if handler is None:
            raise ValueError(f"Unknown tool: {tool_name!r}")

        result = handler(arguments, tenant_id)

        if isinstance(result, str):
            content = result
        else:
            content = json.dumps(result, indent=2)

        return CallToolResult(content=[TextContent(type="text", text=content)])

    except ValueError as exc:
        outcome = "error"
        error_type = "ValueError"
        # Return a safe error message — no internal details exposed.
        return CallToolResult(
            content=[TextContent(type="text", text=f"Error: {exc}")],
            isError=True,
        )
    except Exception:
        outcome = "error"
        error_type = "UnexpectedError"
        app_log.exception("Unexpected error in tool '%s' for tenant '%s'", tool_name, tenant_id)
        return CallToolResult(
            content=[TextContent(type="text", text="An unexpected error occurred.")],
            isError=True,
        )
    finally:
        duration_ms = int((time.monotonic() - start) * 1000)
        log_tool_call(
            call_id=call_id,
            tool_name=tool_name,
            tenant_id=tenant_id,
            input_summary=input_summary,
            outcome=outcome,
            duration_ms=duration_ms,
            error_type=error_type,
        )


# ---------------------------------------------------------------------------
# Entry point
# ---------------------------------------------------------------------------


async def main() -> None:
    try:
        tenant_id = _get_current_tenant()
    except ValueError as exc:
        app_log.error("Invalid MCP_TENANT_ID: %s — aborting.", exc)
        sys.exit(1)

    app_log.info(
        "Starting %s v%s — tenant: %s — quota: %d",
        SERVER_NAME,
        SERVER_VERSION,
        tenant_id,
        TENANT_QUOTA,
    )
    async with stdio_server() as (read_stream, write_stream):
        await server.run(read_stream, write_stream, server.create_initialization_options())


if __name__ == "__main__":
    import asyncio

    asyncio.run(main())
