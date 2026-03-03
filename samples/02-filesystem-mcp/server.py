"""
Sample 02: Filesystem MCP Server

Provides read/write access to a defined workspace directory.

Key security controls:
- Path traversal prevention: all paths are resolved with os.path.realpath
  and then verified to be within the allowed workspace directory.
- File size limits: prevents reading arbitrarily large files.
- Allowlist-based access: no access outside WORKSPACE_DIR.
- Audit logging: every operation is logged.
- Safe errors: path-not-allowed errors don't reveal whether
  files exist outside the workspace.

IMPORTANT: Set MCP_WORKSPACE_DIR to a dedicated directory.
The process should run as an OS user with access only to that directory.
"""

import json
import logging
import os
import sys
import time
import uuid
from pathlib import Path
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

# The directory this server is allowed to access. All operations are
# restricted to files within this directory (and its subdirectories).
WORKSPACE_DIR = os.environ.get("MCP_WORKSPACE_DIR", "/tmp/mcp-workspace")

# Maximum file size to read (prevents memory exhaustion)
MAX_READ_BYTES = 10 * 1024 * 1024  # 10 MB

# Maximum content size to write
MAX_WRITE_BYTES = 10 * 1024 * 1024  # 10 MB

MAX_STRING_LENGTH = 4096
SERVER_NAME = "filesystem-mcp"
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
    path: str,
    outcome: str,
    duration_ms: int,
    detail: str | None = None,
) -> None:
    entry = {
        "timestamp": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
        "call_id": call_id,
        "server": SERVER_NAME,
        "tool": tool_name,
        "path": path,  # Resolved path (safe to log)
        "outcome": outcome,
        "duration_ms": duration_ms,
    }
    if detail:
        entry["detail"] = detail
    audit_log.info(json.dumps(entry))


# ---------------------------------------------------------------------------
# Path validation — THE CRITICAL SECURITY CONTROL
# ---------------------------------------------------------------------------


def get_workspace_root() -> str:
    """Return the resolved, absolute workspace root path."""
    return os.path.realpath(os.path.abspath(WORKSPACE_DIR))


def validate_path(user_path: str) -> str:
    """
    Validate and resolve a user-provided path, ensuring it is within
    the allowed workspace directory.

    Returns the resolved absolute path on success.
    Raises ValueError if the path is outside the workspace.

    This uses os.path.realpath to resolve symlinks, preventing symlink
    attacks that could escape the workspace.
    """
    workspace_root = get_workspace_root()

    # Join with workspace root first, then resolve
    joined = os.path.join(workspace_root, user_path)
    resolved = os.path.realpath(os.path.abspath(joined))

    # Ensure the resolved path is within the workspace
    # We check startswith with a trailing separator to avoid
    # /workspace being matched by /workspace-other
    if not (
        resolved == workspace_root
        or resolved.startswith(workspace_root + os.sep)
    ):
        raise ValueError("Path is outside the allowed workspace")

    return resolved


# ---------------------------------------------------------------------------
# Tool schemas
# ---------------------------------------------------------------------------

PATH_PROPERTY = {
    "type": "string",
    "description": "Relative path within the workspace",
    "minLength": 1,
    "maxLength": MAX_STRING_LENGTH,
}

READ_FILE_SCHEMA: dict[str, Any] = {
    "type": "object",
    "properties": {"path": PATH_PROPERTY},
    "required": ["path"],
    "additionalProperties": False,
}

WRITE_FILE_SCHEMA: dict[str, Any] = {
    "type": "object",
    "properties": {
        "path": PATH_PROPERTY,
        "content": {
            "type": "string",
            "description": "Content to write to the file",
            "maxLength": MAX_WRITE_BYTES,
        },
    },
    "required": ["path", "content"],
    "additionalProperties": False,
}

LIST_DIR_SCHEMA: dict[str, Any] = {
    "type": "object",
    "properties": {
        "path": {
            "type": "string",
            "description": "Relative directory path within the workspace (empty string for root)",
            "maxLength": MAX_STRING_LENGTH,
        }
    },
    "required": [],
    "additionalProperties": False,
}

FILE_EXISTS_SCHEMA: dict[str, Any] = {
    "type": "object",
    "properties": {"path": PATH_PROPERTY},
    "required": ["path"],
    "additionalProperties": False,
}

# ---------------------------------------------------------------------------
# Tool implementations
# ---------------------------------------------------------------------------


def tool_read_file(arguments: dict) -> str:
    raw_path = arguments.get("path", "")
    if not isinstance(raw_path, str):
        raise ValueError("'path' must be a string")

    resolved = validate_path(raw_path)

    if not os.path.exists(resolved):
        raise ValueError(f"File not found: {raw_path!r}")

    if not os.path.isfile(resolved):
        raise ValueError(f"Not a file: {raw_path!r}")

    file_size = os.path.getsize(resolved)
    if file_size > MAX_READ_BYTES:
        raise ValueError(
            f"File too large to read: {file_size:,} bytes "
            f"(maximum is {MAX_READ_BYTES:,} bytes)"
        )

    with open(resolved, "r", encoding="utf-8", errors="replace") as f:
        return f.read()


def tool_write_file(arguments: dict) -> str:
    raw_path = arguments.get("path", "")
    content = arguments.get("content", "")

    if not isinstance(raw_path, str):
        raise ValueError("'path' must be a string")
    if not isinstance(content, str):
        raise ValueError("'content' must be a string")

    resolved = validate_path(raw_path)

    # Create parent directories if they don't exist (still within workspace)
    parent = os.path.dirname(resolved)
    os.makedirs(parent, exist_ok=True)

    with open(resolved, "w", encoding="utf-8") as f:
        f.write(content)

    return f"Successfully wrote {len(content)} characters to {raw_path!r}"


def tool_list_directory(arguments: dict) -> list[dict]:
    raw_path = arguments.get("path", "")

    if not isinstance(raw_path, str):
        raise ValueError("'path' must be a string")

    resolved = validate_path(raw_path) if raw_path else get_workspace_root()

    if not os.path.exists(resolved):
        raise ValueError(f"Directory not found: {raw_path!r}")

    if not os.path.isdir(resolved):
        raise ValueError(f"Not a directory: {raw_path!r}")

    entries = []
    for name in sorted(os.listdir(resolved)):
        full_path = os.path.join(resolved, name)
        entry_type = "directory" if os.path.isdir(full_path) else "file"
        size = os.path.getsize(full_path) if entry_type == "file" else None
        entry = {"name": name, "type": entry_type}
        if size is not None:
            entry["size_bytes"] = size
        entries.append(entry)

    return entries


def tool_file_exists(arguments: dict) -> dict:
    raw_path = arguments.get("path", "")

    if not isinstance(raw_path, str):
        raise ValueError("'path' must be a string")

    try:
        resolved = validate_path(raw_path)
        exists = os.path.exists(resolved)
        is_file = os.path.isfile(resolved) if exists else False
        is_dir = os.path.isdir(resolved) if exists else False
    except ValueError:
        # Don't reveal that the path was outside the workspace;
        # just report it doesn't exist.
        exists = False
        is_file = False
        is_dir = False

    return {"exists": exists, "is_file": is_file, "is_directory": is_dir}


# ---------------------------------------------------------------------------
# Server setup
# ---------------------------------------------------------------------------

TOOLS = [
    Tool(
        name="read_file",
        description="Read the contents of a file within the workspace.",
        inputSchema=READ_FILE_SCHEMA,
    ),
    Tool(
        name="write_file",
        description="Write content to a file within the workspace. Creates the file if it does not exist.",
        inputSchema=WRITE_FILE_SCHEMA,
    ),
    Tool(
        name="list_directory",
        description="List files and directories within the workspace.",
        inputSchema=LIST_DIR_SCHEMA,
    ),
    Tool(
        name="file_exists",
        description="Check whether a file or directory exists within the workspace.",
        inputSchema=FILE_EXISTS_SCHEMA,
    ),
]

TOOL_HANDLERS = {
    "read_file": tool_read_file,
    "write_file": tool_write_file,
    "list_directory": tool_list_directory,
    "file_exists": tool_file_exists,
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
    raw_path = arguments.get("path", "")
    start = time.monotonic()
    outcome = "success"
    error_detail = None

    try:
        handler = TOOL_HANDLERS.get(tool_name)
        if handler is None:
            raise ValueError(f"Unknown tool: {tool_name!r}")

        result = handler(arguments)

        if isinstance(result, str):
            content_text = result
        else:
            content_text = json.dumps(result, indent=2)

        return CallToolResult(content=[TextContent(type="text", text=content_text)])

    except ValueError as exc:
        outcome = "error"
        error_detail = str(exc)
        return CallToolResult(
            content=[TextContent(type="text", text=f"Error: {exc}")],
            isError=True,
        )
    except PermissionError:
        outcome = "denied"
        return CallToolResult(
            content=[TextContent(type="text", text="Permission denied.")],
            isError=True,
        )
    except Exception:
        outcome = "error"
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
            path=str(raw_path),
            outcome=outcome,
            duration_ms=duration_ms,
            detail=error_detail,
        )


# ---------------------------------------------------------------------------
# Entry point
# ---------------------------------------------------------------------------


async def main() -> None:
    workspace_root = get_workspace_root()
    app_log.info(
        "Starting %s v%s — workspace: %s",
        SERVER_NAME,
        SERVER_VERSION,
        workspace_root,
    )

    # Warn if the workspace directory doesn't exist
    if not os.path.isdir(workspace_root):
        app_log.warning(
            "Workspace directory does not exist: %s — creating it.", workspace_root
        )
        os.makedirs(workspace_root, exist_ok=True)

    async with stdio_server() as (read_stream, write_stream):
        await server.run(
            read_stream, write_stream, server.create_initialization_options()
        )


if __name__ == "__main__":
    import asyncio

    asyncio.run(main())
