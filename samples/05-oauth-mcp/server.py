"""
Sample 05: OAuth MCP Server

Demonstrates OAuth 2.0 Bearer token validation in an MCP server, acting as
a resource server that validates incoming tokens before processing requests.

Key security controls:
- Token validation on every call: token must exist, not be expired, and carry
  the required scope for the requested tool.
- Scope enforcement: each tool declares a required scope; mismatched scope
  results in an authorization denied response.
- Token expiry: tokens carry an expires_at timestamp; expired tokens are
  rejected regardless of their scopes.
- No token in responses: token values are never echoed back in any tool
  response or audit log entry.
- Audit logging includes user identity (from the validated token) but NOT the
  token value itself.
- Token rotation hint: if the token is within 5 minutes of expiry a hint is
  included in the response to prompt the client to refresh.

This server reads MCP_BEARER_TOKEN from the environment to identify which
token the caller is using. In production, the token would arrive via the
MCP authorization header or a session credential — not an env var.

PRODUCTION REPLACEMENT GUIDE:
  - TOKEN_STORE dict → replace with calls to your OAuth 2.0 introspection
    endpoint (RFC 7662): POST /introspect with the token, verify the JSON
    response fields: active, exp, scope, sub.
  - The validate_token() function is the single integration point; swap its
    implementation without changing any tool code.
  - Consider token caching with a short TTL to avoid per-call introspection
    latency, but always re-validate expiry from the cached response.
"""

import json
import logging
import os
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
# Configuration
# ---------------------------------------------------------------------------

# The caller passes the Bearer token value via this env var.
# In a real MCP deployment this would come from the Authorization header or
# a session-level credential, not the environment. This env-var approach is
# used here solely to keep the demo self-contained and easy to test.
BEARER_TOKEN = os.environ.get("MCP_BEARER_TOKEN", "")

# How many seconds before expiry counts as "expiring soon" for the rotation hint
TOKEN_ROTATION_WARNING_SECS = 300  # 5 minutes

SERVER_NAME = "oauth-mcp"
SERVER_VERSION = "0.1.0"

# ---------------------------------------------------------------------------
# Logging
# ---------------------------------------------------------------------------

logging.basicConfig(stream=sys.stderr, level=logging.INFO, format="%(message)s")
audit_log = logging.getLogger("mcp.audit")
app_log = logging.getLogger("mcp.app")


def log_tool_call(
    call_id: str,
    tool_name: str,
    input_summary: dict,
    outcome: str,
    duration_ms: int,
    user: str | None = None,
    error_type: str | None = None,
) -> None:
    """
    Emit a structured audit log entry for a tool call.

    Security: 'user' is the identity from the validated token; the token
    value itself is never included in the log entry.
    """
    entry = {
        "timestamp": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
        "call_id": call_id,
        "server": SERVER_NAME,
        "tool": tool_name,
        "input_summary": input_summary,
        "outcome": outcome,
        "duration_ms": duration_ms,
    }
    if user:
        entry["user"] = user  # identity only — never the token value
    if error_type:
        entry["error_type"] = error_type
    audit_log.info(json.dumps(entry))


# ---------------------------------------------------------------------------
# Demo token store
#
# In production, replace this dict lookup with a call to your OAuth 2.0
# token introspection endpoint (RFC 7662).
#
# Each entry represents a validated, active token with:
#   user       : the identity the token was issued to (subject claim)
#   scopes     : set of OAuth scopes granted to this token
#   expires_at : Unix timestamp when the token expires
#
# Tokens expire relative to server start time so the demo remains usable
# regardless of when it is run.
# ---------------------------------------------------------------------------

_SERVER_START = time.time()

TOKEN_STORE: dict[str, dict[str, Any]] = {
    # Read-only token for alice — expires in 1 hour
    "token-read-only": {
        "user": "alice",
        "scopes": {"data:read"},
        "expires_at": _SERVER_START + 3600,
    },
    # Read-write token for bob — expires in 1 hour
    "token-read-write": {
        "user": "bob",
        "scopes": {"data:read", "data:write"},
        "expires_at": _SERVER_START + 3600,
    },
    # Admin token — expires in 1 hour
    "token-admin": {
        "user": "admin",
        "scopes": {"data:read", "data:write", "admin"},
        "expires_at": _SERVER_START + 3600,
    },
    # Already-expired token for charlie (expires_at set to 1 hour before start)
    "token-expired": {
        "user": "charlie",
        "scopes": {"data:read"},
        "expires_at": _SERVER_START - 3600,
    },
}

# ---------------------------------------------------------------------------
# Token validation — THE CRITICAL SECURITY CONTROL
#
# This function is called on EVERY tool invocation before any tool logic
# runs. It is the single enforcement point for authentication and
# authorization. Every tool must pass through it.
#
# In production: replace the TOKEN_STORE lookup with an HTTP call to your
# OAuth 2.0 introspection endpoint and parse the response JSON.
# ---------------------------------------------------------------------------


class AuthError(Exception):
    """Raised when token validation fails for any reason."""


def validate_token(token: str, required_scope: str) -> dict[str, Any]:
    """
    Validate a Bearer token and check that it carries the required scope.

    Returns a dict with token metadata on success:
        {
            "user": str,             # identity — safe to log and return
            "scopes": set[str],      # granted scopes
            "expires_at": float,     # Unix timestamp
            "expiring_soon": bool,   # True if within TOKEN_ROTATION_WARNING_SECS
        }

    Raises AuthError with a caller-safe message on any failure.

    Security notes:
    - We deliberately return the same generic error for "token not found"
      and "token expired" to avoid leaking token existence information.
    - The token value is never included in the raised exception message or
      in any log entry.
    - PRODUCTION: replace TOKEN_STORE lookup with introspection endpoint call.
    """
    if not token:
        raise AuthError("Authorization required: no Bearer token provided")

    # PRODUCTION REPLACEMENT: call your OAuth introspection endpoint here.
    # Example:
    #   response = httpx.post(
    #       INTROSPECTION_ENDPOINT,
    #       data={"token": token},
    #       auth=(CLIENT_ID, CLIENT_SECRET),
    #   )
    #   info = response.json()
    #   if not info.get("active"):
    #       raise AuthError("Token is not active")
    token_info = TOKEN_STORE.get(token)

    if token_info is None:
        # Do NOT distinguish "unknown token" from "expired token" to avoid
        # leaking information about which tokens exist.
        raise AuthError("Authorization failed: invalid or expired token")

    now = time.time()
    if now >= token_info["expires_at"]:
        raise AuthError("Authorization failed: invalid or expired token")

    if required_scope not in token_info["scopes"]:
        # Scope mismatch: reveal the required scope (already public via tool
        # descriptions) but not what scopes the token actually holds.
        raise AuthError(
            f"Authorization denied: token does not have required scope '{required_scope}'"
        )

    expiring_soon = (token_info["expires_at"] - now) <= TOKEN_ROTATION_WARNING_SECS

    return {
        "user": token_info["user"],
        "scopes": token_info["scopes"],
        "expires_at": token_info["expires_at"],
        "expiring_soon": expiring_soon,
    }


def maybe_rotation_hint(token_ctx: dict) -> str | None:
    """
    Return a rotation hint string if the token is close to expiry.

    This is a UX signal to the client/caller — it does not expose the token
    value or any sensitive credential information.
    """
    if token_ctx.get("expiring_soon"):
        seconds_left = int(token_ctx["expires_at"] - time.time())
        return (
            f"[Notice: your token expires in approximately {seconds_left} seconds. "
            "Please refresh your token soon.]"
        )
    return None


# ---------------------------------------------------------------------------
# Mock data store
#
# In production these would be real database or API calls, gated behind
# the authorization check that has already succeeded.
# ---------------------------------------------------------------------------

_MOCK_PROFILES: dict[str, dict[str, Any]] = {
    "alice": {
        "user": "alice",
        "email": "alice@example.com",
        "display_name": "Alice Smith",
        "role": "viewer",
        "created_at": "2024-01-01T00:00:00Z",
    },
    "bob": {
        "user": "bob",
        "email": "bob@example.com",
        "display_name": "Bob Jones",
        "role": "editor",
        "created_at": "2024-01-02T00:00:00Z",
    },
    "admin": {
        "user": "admin",
        "email": "admin@example.com",
        "display_name": "System Admin",
        "role": "admin",
        "created_at": "2023-06-15T00:00:00Z",
    },
}

_MOCK_RESOURCES: dict[str, list[dict[str, Any]]] = {
    "alice": [
        {"id": "res-001", "name": "Alice's Report Q1", "type": "document"},
        {"id": "res-002", "name": "Alice's Dashboard",  "type": "dashboard"},
    ],
    "bob": [
        {"id": "res-003", "name": "Bob's Analysis",     "type": "document"},
    ],
    "admin": [
        {"id": "res-004", "name": "System Overview",    "type": "dashboard"},
        {"id": "res-005", "name": "Audit Report",       "type": "document"},
    ],
}

# ---------------------------------------------------------------------------
# Tool schemas
# ---------------------------------------------------------------------------

EMPTY_SCHEMA: dict[str, Any] = {
    "type": "object",
    "properties": {},
    "additionalProperties": False,
}

CREATE_RESOURCE_SCHEMA: dict[str, Any] = {
    "type": "object",
    "properties": {
        "name": {
            "type": "string",
            "description": "Name for the new resource.",
            "minLength": 1,
            "maxLength": 128,
        },
        "type": {
            "type": "string",
            "description": "Type of resource to create.",
            "enum": ["document", "dashboard", "report"],
        },
    },
    "required": ["name", "type"],
    "additionalProperties": False,
}

# ---------------------------------------------------------------------------
# Tool scope map — each tool declares its required OAuth scope
# ---------------------------------------------------------------------------

TOOL_SCOPES: dict[str, str] = {
    "get_profile":      "data:read",
    "list_resources":   "data:read",
    "create_resource":  "data:write",
    "admin_status":     "admin",
}

# ---------------------------------------------------------------------------
# Tool implementations
#
# Each tool receives a pre-validated token context dict from handle_call_tool.
# They never access the raw token value.
# ---------------------------------------------------------------------------


def tool_get_profile(arguments: dict, token_ctx: dict) -> dict:
    """Return the authenticated user's mock profile."""
    user = token_ctx["user"]
    profile = _MOCK_PROFILES.get(user, {"user": user, "note": "Profile not found in demo store"})
    result: dict[str, Any] = {"profile": profile}
    hint = maybe_rotation_hint(token_ctx)
    if hint:
        result["_notice"] = hint
    return result


def tool_list_resources(arguments: dict, token_ctx: dict) -> dict:
    """Return a list of mock resources owned by the authenticated user."""
    user = token_ctx["user"]
    resources = _MOCK_RESOURCES.get(user, [])
    result: dict[str, Any] = {
        "user": user,
        "resource_count": len(resources),
        "resources": resources,
    }
    hint = maybe_rotation_hint(token_ctx)
    if hint:
        result["_notice"] = hint
    return result


def tool_create_resource(arguments: dict, token_ctx: dict) -> dict:
    """
    Create a mock resource for the authenticated user.

    The resource is not persisted between calls (demo only). In production
    this would write to a database and return the canonical resource ID.
    """
    name = arguments.get("name")
    resource_type = arguments.get("type")

    if not isinstance(name, str) or not name:
        raise ValueError("'name' must be a non-empty string")
    if resource_type not in ("document", "dashboard", "report"):
        raise ValueError("'type' must be one of: document, dashboard, report")

    user = token_ctx["user"]
    resource_id = f"res-{uuid.uuid4().hex[:8]}"

    result: dict[str, Any] = {
        "status": "created",
        "resource": {
            "id": resource_id,
            "name": name,
            "type": resource_type,
            "owner": user,
            "created_at": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
        },
    }
    hint = maybe_rotation_hint(token_ctx)
    if hint:
        result["_notice"] = hint
    return result


def tool_admin_status(arguments: dict, token_ctx: dict) -> dict:
    """Return mock system status information (admin scope required)."""
    result: dict[str, Any] = {
        "system_status": "operational",
        "server": SERVER_NAME,
        "version": SERVER_VERSION,
        "uptime_seconds": int(time.time() - _SERVER_START),
        "active_token_count": len(TOKEN_STORE),
        "current_time": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
        "requested_by": token_ctx["user"],
    }
    hint = maybe_rotation_hint(token_ctx)
    if hint:
        result["_notice"] = hint
    return result


# ---------------------------------------------------------------------------
# Server setup
# ---------------------------------------------------------------------------

TOOLS = [
    Tool(
        name="get_profile",
        description=(
            "Return the authenticated user's profile. "
            "Requires scope: data:read."
        ),
        inputSchema=EMPTY_SCHEMA,
    ),
    Tool(
        name="list_resources",
        description=(
            "List resources owned by the authenticated user. "
            "Requires scope: data:read."
        ),
        inputSchema=EMPTY_SCHEMA,
    ),
    Tool(
        name="create_resource",
        description=(
            "Create a new resource for the authenticated user. "
            "Requires scope: data:write."
        ),
        inputSchema=CREATE_RESOURCE_SCHEMA,
    ),
    Tool(
        name="admin_status",
        description=(
            "Return system status information. "
            "Requires scope: admin."
        ),
        inputSchema=EMPTY_SCHEMA,
    ),
]

TOOL_HANDLERS: dict[str, Any] = {
    "get_profile":     tool_get_profile,
    "list_resources":  tool_list_resources,
    "create_resource": tool_create_resource,
    "admin_status":    tool_admin_status,
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
    authenticated_user: str | None = None

    # Build a safe input summary for audit logging
    input_summary = {
        k: (v[:80] + "..." if isinstance(v, str) and len(v) > 80 else v)
        for k, v in arguments.items()
    }

    try:
        handler = TOOL_HANDLERS.get(tool_name)
        if handler is None:
            raise ValueError(f"Unknown tool: {tool_name!r}")

        # Determine required scope for this tool
        required_scope = TOOL_SCOPES.get(tool_name)
        if required_scope is None:
            raise ValueError(f"No scope defined for tool: {tool_name!r}")

        # Security: validate token on EVERY call before any tool logic runs.
        # This is the authentication and authorization gate.
        # The token value is never stored or logged; only the user identity is.
        token_ctx = validate_token(BEARER_TOKEN, required_scope)
        authenticated_user = token_ctx["user"]

        result = handler(arguments, token_ctx)

        if isinstance(result, str):
            content_text = result
        else:
            content_text = json.dumps(result, indent=2)

        return CallToolResult(content=[TextContent(type="text", text=content_text)])

    except AuthError as exc:
        outcome = "denied"
        error_type = "AuthError"
        # Return the auth error message (already caller-safe — no token values)
        return CallToolResult(
            content=[TextContent(type="text", text=f"Error: {exc}")],
            isError=True,
        )
    except ValueError as exc:
        outcome = "error"
        error_type = "ValueError"
        return CallToolResult(
            content=[TextContent(type="text", text=f"Error: {exc}")],
            isError=True,
        )
    except Exception:
        outcome = "error"
        error_type = "Exception"
        app_log.exception("Unexpected error in tool '%s'", tool_name)
        return CallToolResult(
            content=[TextContent(type="text", text="An unexpected error occurred.")],
            isError=True,
        )
    finally:
        duration_ms = int((time.monotonic() - start) * 1000)
        log_tool_call(
            call_id=call_id,
            tool_name=tool_name,
            input_summary=input_summary,
            outcome=outcome,
            duration_ms=duration_ms,
            user=authenticated_user,  # identity only — never the token value
            error_type=error_type,
        )


# ---------------------------------------------------------------------------
# Entry point
# ---------------------------------------------------------------------------


async def main() -> None:
    app_log.info("Starting %s v%s", SERVER_NAME, SERVER_VERSION)

    if not BEARER_TOKEN:
        app_log.warning(
            "MCP_BEARER_TOKEN is not set. All tool calls will fail with AuthError. "
            "Set MCP_BEARER_TOKEN to one of: token-read-only, token-read-write, "
            "token-admin, or token-expired (to test expiry rejection)."
        )
    else:
        # Log that a token is configured — but NOT the token value itself
        app_log.info("Bearer token configured (value not logged)")

    async with stdio_server() as (read_stream, write_stream):
        await server.run(
            read_stream, write_stream, server.create_initialization_options()
        )


if __name__ == "__main__":
    import asyncio

    asyncio.run(main())
