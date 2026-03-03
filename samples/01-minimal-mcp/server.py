"""
Sample 01: Minimal Secure MCP Server

A reference implementation demonstrating foundational security controls:
- Strict input schema validation
- Input size limits
- Structured audit logging
- Safe error responses (no internal details exposed)
- Graceful error handling

This sample intentionally does nothing interesting — it's a secure skeleton
you can build on.
"""

import json
import logging
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
# Constants
# ---------------------------------------------------------------------------

MAX_STRING_LENGTH = 10_000
SERVER_NAME = "minimal-mcp"
SERVER_VERSION = "0.1.0"

# ---------------------------------------------------------------------------
# Tool schemas
# ---------------------------------------------------------------------------

ECHO_SCHEMA: dict[str, Any] = {
    "type": "object",
    "properties": {
        "message": {
            "type": "string",
            "description": "The message to echo back",
            "minLength": 1,
            "maxLength": MAX_STRING_LENGTH,
        }
    },
    "required": ["message"],
    "additionalProperties": False,  # Reject unexpected fields
}

GET_INFO_SCHEMA: dict[str, Any] = {
    "type": "object",
    "properties": {},
    "additionalProperties": False,
}

# ---------------------------------------------------------------------------
# Audit logging
# ---------------------------------------------------------------------------


def log_tool_call(
    call_id: str,
    tool_name: str,
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


def validate_string_length(value: str, field_name: str) -> None:
    """Raise ValueError if string exceeds the maximum allowed length."""
    if len(value) > MAX_STRING_LENGTH:
        raise ValueError(
            f"'{field_name}' exceeds maximum length of {MAX_STRING_LENGTH} characters"
        )


# ---------------------------------------------------------------------------
# Tool implementations
# ---------------------------------------------------------------------------


def tool_echo(arguments: dict) -> str:
    """Echo the provided message back to the caller."""
    message = arguments.get("message")
    if not isinstance(message, str) or not message:
        raise ValueError("'message' must be a non-empty string")
    validate_string_length(message, "message")
    return message


def tool_get_info(_arguments: dict) -> dict:
    """Return static information about this MCP server."""
    return {
        "name": SERVER_NAME,
        "version": SERVER_VERSION,
        "description": "Minimal secure MCP reference implementation",
        "tools": ["echo", "get_info"],
    }


# ---------------------------------------------------------------------------
# Server setup
# ---------------------------------------------------------------------------

TOOLS = [
    Tool(
        name="echo",
        description="Echoes the provided message back. Use for testing connectivity.",
        inputSchema=ECHO_SCHEMA,
    ),
    Tool(
        name="get_info",
        description="Returns information about this MCP server.",
        inputSchema=GET_INFO_SCHEMA,
    ),
]

TOOL_HANDLERS = {
    "echo": tool_echo,
    "get_info": tool_get_info,
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

    # Sanitize arguments for logging — avoid logging sensitive values
    input_summary = {
        k: (v[:100] + "..." if isinstance(v, str) and len(v) > 100 else v)
        for k, v in arguments.items()
    }

    try:
        handler = TOOL_HANDLERS.get(tool_name)
        if handler is None:
            raise ValueError(f"Unknown tool: {tool_name!r}")

        result = handler(arguments)

        # Format result as text
        if isinstance(result, str):
            content = result
        else:
            content = json.dumps(result, indent=2)

        return CallToolResult(content=[TextContent(type="text", text=content)])

    except ValueError as exc:
        outcome = "error"
        error_type = "ValueError"
        # Return a safe error message — no internal details
        return CallToolResult(
            content=[TextContent(type="text", text=f"Error: {exc}")],
            isError=True,
        )
    except Exception as exc:
        outcome = "error"
        error_type = type(exc).__name__
        # Log the full exception server-side, return a generic message
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
            error_type=error_type,
        )


# ---------------------------------------------------------------------------
# Entry point
# ---------------------------------------------------------------------------


async def main() -> None:
    app_log.info("Starting %s v%s", SERVER_NAME, SERVER_VERSION)
    async with stdio_server() as (read_stream, write_stream):
        await server.run(read_stream, write_stream, server.create_initialization_options())


if __name__ == "__main__":
    import asyncio
    asyncio.run(main())
