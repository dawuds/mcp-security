# Sample 03: API Gateway MCP

An MCP server that acts as a gateway to external HTTP APIs, demonstrating security controls for outbound API integration.

## What It Does

Exposes these tools:
- `http_get` — Fetch a URL and return the response (with SSRF protection)
- `http_post` — Post JSON data to a URL (with SSRF protection)

## Security Controls Demonstrated

| Control | Implementation |
|---------|---------------|
| SSRF prevention | URL validation blocks private IPs, internal ranges, dangerous schemes |
| Input validation | Strict schema validation, size limits on request/response |
| Response sanitization | Responses are truncated and wrapped before returning to AI model |
| Auth header protection | Authorization headers in requests are blocked (prevents credential leakage) |
| Rate limiting | Simple per-session rate limiting |
| Audit logging | Every outbound request logged |
| Timeout enforcement | Configurable request timeout prevents hanging |
| Allowlist mode | Optional: restrict to a list of approved domains |

## Configuration

```bash
# Required: set an allowlist of permitted domains (optional but recommended)
export MCP_ALLOWED_DOMAINS="api.example.com,api.another.com"

# Request timeout in seconds (default: 10)
export MCP_REQUEST_TIMEOUT=10

# Max response size in bytes (default: 1MB)
export MCP_MAX_RESPONSE_BYTES=1048576
```

## Requirements

```
mcp>=1.0.0
httpx>=0.27.0
```

## Running

```bash
pip install -r requirements.txt
python server.py
```

## Security Note

This sample demonstrates SSRF prevention for outbound requests. For production use:
- Always configure `MCP_ALLOWED_DOMAINS` to restrict to known-good APIs
- Consider DNS rebinding protection (re-resolve hostnames before connecting)
- Review what data is being sent to and received from external APIs
