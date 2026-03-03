"""
Sample 03: API Gateway MCP Server

Acts as a gateway to external HTTP APIs with security controls for
outbound requests.

Key security controls:
- SSRF prevention: blocks requests to private IPs, internal ranges,
  dangerous schemes, and cloud metadata endpoints.
- Allowlist mode: optionally restricts requests to approved domains.
- Response sanitization: truncates large responses before returning
  to AI model context to limit prompt injection surface.
- Auth header protection: blocks forwarding of Authorization headers
  (prevents credential exfiltration).
- Rate limiting: per-session call limits.
- Timeout: configurable request timeout.
- Audit logging: every outbound request logged.
"""

import ipaddress
import json
import logging
import os
import sys
import time
import uuid
from collections import defaultdict
from typing import Any
from urllib.parse import urlparse

import httpx

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

# Comma-separated allowlist of permitted domains (empty = no allowlist)
ALLOWED_DOMAINS_RAW = os.environ.get("MCP_ALLOWED_DOMAINS", "")
ALLOWED_DOMAINS: set[str] = (
    {d.strip().lower() for d in ALLOWED_DOMAINS_RAW.split(",") if d.strip()}
    if ALLOWED_DOMAINS_RAW
    else set()
)

REQUEST_TIMEOUT = float(os.environ.get("MCP_REQUEST_TIMEOUT", "10"))
MAX_RESPONSE_BYTES = int(os.environ.get("MCP_MAX_RESPONSE_BYTES", str(1024 * 1024)))

# Rate limiting: max calls per session per minute
RATE_LIMIT_PER_MINUTE = 30

SERVER_NAME = "api-gateway-mcp"
SERVER_VERSION = "0.1.0"

# ---------------------------------------------------------------------------
# Logging
# ---------------------------------------------------------------------------

logging.basicConfig(stream=sys.stderr, level=logging.INFO, format="%(message)s")
audit_log = logging.getLogger("mcp.audit")
app_log = logging.getLogger("mcp.app")

# ---------------------------------------------------------------------------
# SSRF prevention
# ---------------------------------------------------------------------------

BLOCKED_SCHEMES = {"file", "ftp", "gopher", "dict", "ldap", "ldaps", "sftp", "tftp"}
ALLOWED_SCHEMES = {"http", "https"}

# Private, loopback, and link-local IP ranges
PRIVATE_NETWORKS = [
    ipaddress.ip_network("10.0.0.0/8"),
    ipaddress.ip_network("172.16.0.0/12"),
    ipaddress.ip_network("192.168.0.0/16"),
    ipaddress.ip_network("127.0.0.0/8"),       # Loopback
    ipaddress.ip_network("169.254.0.0/16"),    # Link-local (AWS metadata default)
    ipaddress.ip_network("100.64.0.0/10"),     # Shared address space (RFC 6598)
    ipaddress.ip_network("::1/128"),           # IPv6 loopback
    ipaddress.ip_network("fc00::/7"),          # IPv6 ULA
    ipaddress.ip_network("fe80::/10"),         # IPv6 link-local
]

# Known cloud metadata endpoints (block by hostname)
BLOCKED_HOSTNAMES = {
    "metadata.google.internal",
    "metadata.internal",
    "169.254.169.254",  # AWS/Azure/GCP metadata
    "100.100.100.200",  # Alibaba Cloud metadata
}


def validate_url(url: str) -> str:
    """
    Validate a URL for safety before making an outbound request.

    Blocks:
    - Non-HTTP/HTTPS schemes
    - Private, loopback, and link-local IP ranges
    - Known cloud metadata endpoints
    - Domains not in the allowlist (if allowlist is configured)

    Returns the validated URL or raises ValueError.
    """
    parsed = urlparse(url)

    if parsed.scheme not in ALLOWED_SCHEMES:
        raise ValueError(f"URL scheme not permitted: {parsed.scheme!r}")

    host = parsed.hostname
    if not host:
        raise ValueError("URL has no hostname")

    host_lower = host.lower()

    if host_lower in BLOCKED_HOSTNAMES:
        raise ValueError(f"Hostname is not permitted: {host!r}")

    # Check allowlist if configured
    if ALLOWED_DOMAINS and host_lower not in ALLOWED_DOMAINS:
        raise ValueError(
            f"Domain not in allowlist: {host!r}. "
            f"Allowed: {', '.join(sorted(ALLOWED_DOMAINS))}"
        )

    # Check if host is an IP address in a private range
    try:
        ip = ipaddress.ip_address(host)
        for network in PRIVATE_NETWORKS:
            if ip in network:
                raise ValueError(f"URL targets a private/internal IP address: {ip}")
    except ValueError as exc:
        # Re-raise private IP errors
        if "private" in str(exc) or "internal" in str(exc):
            raise
        # Otherwise, it's a hostname (not an IP) — allow it to proceed.
        # Note: for production, implement DNS rebinding protection by
        # resolving the hostname and re-checking the resolved IP here.

    return url


# ---------------------------------------------------------------------------
# Rate limiting (simple in-memory, per-session)
# ---------------------------------------------------------------------------

# Maps session_id -> list of call timestamps
_rate_limit_store: dict[str, list[float]] = defaultdict(list)


def check_rate_limit(session_id: str) -> None:
    """Raise ValueError if the session has exceeded the rate limit."""
    now = time.monotonic()
    window_start = now - 60.0
    calls = _rate_limit_store[session_id]

    # Remove calls outside the window
    calls[:] = [t for t in calls if t > window_start]

    if len(calls) >= RATE_LIMIT_PER_MINUTE:
        raise ValueError(
            f"Rate limit exceeded: maximum {RATE_LIMIT_PER_MINUTE} calls per minute"
        )

    calls.append(now)


# ---------------------------------------------------------------------------
# Tool schemas
# ---------------------------------------------------------------------------

URL_PROPERTY = {
    "type": "string",
    "description": "The URL to request. Must be HTTP or HTTPS.",
    "minLength": 10,
    "maxLength": 2048,
}

HTTP_GET_SCHEMA: dict[str, Any] = {
    "type": "object",
    "properties": {
        "url": URL_PROPERTY,
        "headers": {
            "type": "object",
            "description": "Optional HTTP headers (Authorization header is not permitted)",
            "additionalProperties": {"type": "string"},
        },
    },
    "required": ["url"],
    "additionalProperties": False,
}

HTTP_POST_SCHEMA: dict[str, Any] = {
    "type": "object",
    "properties": {
        "url": URL_PROPERTY,
        "body": {
            "type": "object",
            "description": "JSON body to POST",
        },
        "headers": {
            "type": "object",
            "description": "Optional HTTP headers (Authorization header is not permitted)",
            "additionalProperties": {"type": "string"},
        },
    },
    "required": ["url", "body"],
    "additionalProperties": False,
}

# ---------------------------------------------------------------------------
# Tool implementations
# ---------------------------------------------------------------------------

# Block headers that could be used to forward credentials or cause harm
BLOCKED_HEADERS = {"authorization", "cookie", "set-cookie", "x-api-key", "x-auth-token"}


def sanitize_headers(headers: dict | None) -> dict:
    """Remove disallowed headers from a user-provided headers dict."""
    if not headers:
        return {}
    return {
        k: v
        for k, v in headers.items()
        if k.lower() not in BLOCKED_HEADERS and isinstance(v, str)
    }


def sanitize_response(content: bytes, status_code: int, content_type: str) -> str:
    """
    Sanitize and truncate API response before returning to AI model.

    Wrapping in explicit delimiters signals to the AI model that this
    is external data, not instructions — reducing prompt injection risk.
    """
    truncated = False
    if len(content) > MAX_RESPONSE_BYTES:
        content = content[:MAX_RESPONSE_BYTES]
        truncated = True

    try:
        text = content.decode("utf-8", errors="replace")
    except Exception:
        text = repr(content[:1000])

    result = f"<api_response status={status_code} content_type={content_type!r}>\n{text}\n</api_response>"
    if truncated:
        result += f"\n[Response truncated at {MAX_RESPONSE_BYTES:,} bytes]"
    return result


async def tool_http_get(arguments: dict, session_id: str) -> str:
    url = arguments.get("url", "")
    raw_headers = arguments.get("headers")

    if not isinstance(url, str):
        raise ValueError("'url' must be a string")

    check_rate_limit(session_id)
    validated_url = validate_url(url)
    safe_headers = sanitize_headers(raw_headers)

    async with httpx.AsyncClient(timeout=REQUEST_TIMEOUT, follow_redirects=True) as client:
        response = await client.get(validated_url, headers=safe_headers)

    content_type = response.headers.get("content-type", "unknown")
    return sanitize_response(response.content, response.status_code, content_type)


async def tool_http_post(arguments: dict, session_id: str) -> str:
    url = arguments.get("url", "")
    body = arguments.get("body")
    raw_headers = arguments.get("headers")

    if not isinstance(url, str):
        raise ValueError("'url' must be a string")
    if not isinstance(body, dict):
        raise ValueError("'body' must be a JSON object")

    check_rate_limit(session_id)
    validated_url = validate_url(url)
    safe_headers = sanitize_headers(raw_headers)

    async with httpx.AsyncClient(timeout=REQUEST_TIMEOUT, follow_redirects=True) as client:
        response = await client.post(validated_url, json=body, headers=safe_headers)

    content_type = response.headers.get("content-type", "unknown")
    return sanitize_response(response.content, response.status_code, content_type)


# ---------------------------------------------------------------------------
# Server setup
# ---------------------------------------------------------------------------

TOOLS = [
    Tool(
        name="http_get",
        description="Make an HTTP GET request to an external URL and return the response.",
        inputSchema=HTTP_GET_SCHEMA,
    ),
    Tool(
        name="http_post",
        description="Make an HTTP POST request with a JSON body to an external URL.",
        inputSchema=HTTP_POST_SCHEMA,
    ),
]

server = Server(SERVER_NAME)

# We use a simple session ID from the server instance for rate limiting
# (In production, derive this from the authenticated user identity)
_session_id = str(uuid.uuid4())


@server.list_tools()
async def handle_list_tools(request: ListToolsRequest) -> ListToolsResult:
    return ListToolsResult(tools=TOOLS)


@server.call_tool()
async def handle_call_tool(request: CallToolRequest) -> CallToolResult:
    call_id = str(uuid.uuid4())
    tool_name = request.params.name
    arguments = request.params.arguments or {}
    raw_url = arguments.get("url", "")
    start = time.monotonic()
    outcome = "success"
    error_detail = None

    try:
        if tool_name == "http_get":
            result = await tool_http_get(arguments, _session_id)
        elif tool_name == "http_post":
            result = await tool_http_post(arguments, _session_id)
        else:
            raise ValueError(f"Unknown tool: {tool_name!r}")

        return CallToolResult(content=[TextContent(type="text", text=result)])

    except ValueError as exc:
        outcome = "error"
        error_detail = str(exc)
        return CallToolResult(
            content=[TextContent(type="text", text=f"Error: {exc}")],
            isError=True,
        )
    except httpx.TimeoutException:
        outcome = "error"
        error_detail = "Request timed out"
        return CallToolResult(
            content=[TextContent(type="text", text="Error: The request timed out.")],
            isError=True,
        )
    except httpx.RequestError as exc:
        outcome = "error"
        error_detail = f"Request error: {type(exc).__name__}"
        return CallToolResult(
            content=[TextContent(type="text", text="Error: The request failed.")],
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
        # Log the URL (already validated or rejected before network call)
        audit_log.info(json.dumps({
            "timestamp": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
            "call_id": call_id,
            "server": SERVER_NAME,
            "tool": tool_name,
            "url": str(raw_url)[:500],  # Truncate to 500 chars for logging
            "outcome": outcome,
            "duration_ms": duration_ms,
            "detail": error_detail,
        }))


# ---------------------------------------------------------------------------
# Entry point
# ---------------------------------------------------------------------------


async def main() -> None:
    app_log.info("Starting %s v%s", SERVER_NAME, SERVER_VERSION)
    if ALLOWED_DOMAINS:
        app_log.info("Domain allowlist: %s", ", ".join(sorted(ALLOWED_DOMAINS)))
    else:
        app_log.warning(
            "No domain allowlist configured (MCP_ALLOWED_DOMAINS). "
            "All non-private domains are reachable."
        )

    async with stdio_server() as (read_stream, write_stream):
        await server.run(
            read_stream, write_stream, server.create_initialization_options()
        )


if __name__ == "__main__":
    import asyncio

    asyncio.run(main())
