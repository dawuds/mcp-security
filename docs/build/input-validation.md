# Input Validation for MCP Servers

MCP tool arguments are constructed by an AI model. They can be influenced by adversarial content in the AI's context. Never trust tool inputs.

---

## Validation Layers

Apply validation in this order:

```
Raw tool call arguments
        ↓
1. Schema validation (type, format, required fields)
        ↓
2. Business rule validation (allowed values, ranges)
        ↓
3. Contextual validation (path allowlists, URL safety, etc.)
        ↓
Proceed with execution
```

---

## 1. JSON Schema Validation

Define strict schemas for every tool. Use `additionalProperties: false` to reject unexpected fields.

```python
from mcp.server import Server
from mcp.types import Tool
import jsonschema

READ_FILE_SCHEMA = {
    "type": "object",
    "properties": {
        "path": {
            "type": "string",
            "minLength": 1,
            "maxLength": 4096
        }
    },
    "required": ["path"],
    "additionalProperties": False
}

def validate_tool_input(schema: dict, data: dict) -> None:
    try:
        jsonschema.validate(data, schema)
    except jsonschema.ValidationError as e:
        raise ValueError(f"Invalid tool input: {e.message}")
```

---

## 2. File Path Validation

Path traversal is the most common filesystem MCP vulnerability.

```python
import os

ALLOWED_BASE_DIR = "/var/mcp/workspaces"

def validate_path(user_path: str) -> str:
    """
    Validates and resolves a user-provided path, ensuring it stays
    within the allowed base directory.

    Returns the resolved absolute path, or raises ValueError.
    """
    # Join with base directory first
    joined = os.path.join(ALLOWED_BASE_DIR, user_path)
    # Resolve symlinks and normalize (removes .., //, etc.)
    resolved = os.path.realpath(joined)
    # Ensure it starts with the allowed base
    allowed_real = os.path.realpath(ALLOWED_BASE_DIR)
    if not resolved.startswith(allowed_real + os.sep) and resolved != allowed_real:
        raise ValueError(f"Path traversal detected: {user_path!r}")
    return resolved
```

**Common bypass attempts to guard against:**
- `../../etc/passwd` — directory traversal
- `/etc/passwd` — absolute path
- `./subdir/../../etc/passwd` — normalized traversal
- Symlinks pointing outside the allowed directory (handled by `realpath`)

---

## 3. URL Validation (SSRF Prevention)

If your MCP server fetches URLs, validate them to prevent Server-Side Request Forgery (SSRF).

```python
import ipaddress
from urllib.parse import urlparse

ALLOWED_SCHEMES = {"https"}
BLOCKED_HOSTS = {"localhost", "127.0.0.1", "0.0.0.0"}
PRIVATE_NETWORKS = [
    ipaddress.ip_network("10.0.0.0/8"),
    ipaddress.ip_network("172.16.0.0/12"),
    ipaddress.ip_network("192.168.0.0/16"),
    ipaddress.ip_network("169.254.0.0/16"),  # link-local
    ipaddress.ip_network("::1/128"),          # IPv6 loopback
    ipaddress.ip_network("fc00::/7"),         # IPv6 ULA
]

def validate_url(url: str) -> str:
    parsed = urlparse(url)

    if parsed.scheme not in ALLOWED_SCHEMES:
        raise ValueError(f"URL scheme not allowed: {parsed.scheme!r}")

    host = parsed.hostname
    if not host:
        raise ValueError("URL has no hostname")

    if host.lower() in BLOCKED_HOSTS:
        raise ValueError(f"Blocked host: {host!r}")

    # Check if host resolves to a private IP
    try:
        addr = ipaddress.ip_address(host)
        for network in PRIVATE_NETWORKS:
            if addr in network:
                raise ValueError(f"URL resolves to private/internal address: {addr}")
    except ValueError as e:
        if "not a valid IP" not in str(e):
            raise
        # hostname (not IP) — DNS resolution check should happen at fetch time
        # Consider using a DNS rebinding-resistant approach in production

    return url
```

---

## 4. String Sanitization

For strings that will be used in system operations:

**Shell command injection prevention:**
```python
import subprocess

# NEVER do this:
# os.system(f"grep {user_input} logfile.txt")

# Use subprocess with argument lists, never shell=True:
result = subprocess.run(
    ["grep", "--", user_input, "logfile.txt"],
    capture_output=True,
    text=True,
    timeout=10
)
```

**SQL injection prevention:**
```python
# NEVER do this:
# cursor.execute(f"SELECT * FROM users WHERE id = {user_id}")

# Use parameterized queries:
cursor.execute("SELECT * FROM users WHERE id = %s", (user_id,))
```

---

## 5. Size and Rate Limits

Prevent resource exhaustion:

```python
MAX_FILE_SIZE_BYTES = 10 * 1024 * 1024  # 10 MB
MAX_RESULTS = 1000
MAX_STRING_LENGTH = 10_000

def read_file(path: str) -> str:
    validated_path = validate_path(path)
    size = os.path.getsize(validated_path)
    if size > MAX_FILE_SIZE_BYTES:
        raise ValueError(f"File too large: {size} bytes (max {MAX_FILE_SIZE_BYTES})")
    with open(validated_path) as f:
        return f.read()
```

---

## 6. Output Sanitization

What you return to the AI model is as important as what you accept:

```python
def sanitize_for_ai_context(content: str) -> str:
    """
    Sanitizes content before returning it to the AI model context.
    Reduces prompt injection risk from retrieved data.
    """
    # Truncate to a reasonable size
    if len(content) > 50_000:
        content = content[:50_000] + "\n[... content truncated ...]"

    # Optionally: wrap in explicit delimiters to signal to the model this is data
    return f"<retrieved_content>\n{content}\n</retrieved_content>"
```

---

## Validation Failure Handling

- Return a clear error message to the caller (without exposing internal paths or logic)
- Log the failure with: tool name, raw input (sanitized for logging), reason, timestamp
- Do NOT silently skip validation or return partial results

```python
def safe_tool_call(tool_name: str, args: dict):
    try:
        validate_tool_input(SCHEMAS[tool_name], args)
        return execute_tool(tool_name, args)
    except ValueError as e:
        logger.warning("Validation failure", extra={
            "tool": tool_name,
            "reason": str(e),
            # Log safe repr of args, not raw values that may contain secrets
        })
        return {"error": f"Invalid input: {e}"}
```

---

## Related

- [Secure Design Principles](secure-design.md)
- [Authorization](authorization.md)
- [Sample: Filesystem MCP](../../samples/02-filesystem-mcp/README.md)
