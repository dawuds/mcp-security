# Sample 05: OAuth MCP

An MCP server demonstrating OAuth 2.0 Bearer token validation, acting as a resource server that authenticates and authorizes every tool call before processing it.

## What It Does

Exposes these tools, each requiring a specific OAuth scope:

| Tool | Required Scope | Description |
|------|---------------|-------------|
| `get_profile` | `data:read` | Return the authenticated user's mock profile |
| `list_resources` | `data:read` | List resources owned by the authenticated user |
| `create_resource` | `data:write` | Create a mock resource |
| `admin_status` | `admin` | Return system status information |

Every tool call is rejected if the token is missing, expired, or lacks the required scope.

## Security Controls Demonstrated

| Control | Implementation |
|---------|---------------|
| Token validation on every call | `validate_token()` called at the start of every `handle_call_tool` invocation |
| Scope enforcement | Each tool declares a required scope; callers with insufficient scope are denied |
| Token expiry | `expires_at` timestamp checked on every call; expired tokens rejected |
| No token in responses | Token values never appear in tool responses or audit log entries |
| Identity-aware audit logging | Audit log records the authenticated user identity but not the token value |
| Token rotation hint | Responses include a notice when the token is within 5 minutes of expiry |
| Generic auth error messages | "Invalid or expired token" avoids leaking which tokens exist |

## Demo Token Store

The server ships with four hardcoded tokens for demonstration. All valid tokens expire 1 hour after the server starts.

| Token | User | Scopes | Status |
|-------|------|--------|--------|
| `token-read-only` | alice | `data:read` | Valid for 1 hour |
| `token-read-write` | bob | `data:read`, `data:write` | Valid for 1 hour |
| `token-admin` | admin | `data:read`, `data:write`, `admin` | Valid for 1 hour |
| `token-expired` | charlie | `data:read` | Already expired |

## Configuration

```bash
# Set the Bearer token the server will accept for this session.
# In production this arrives via the Authorization header, not an env var.
export MCP_BEARER_TOKEN=token-read-write
```

## Requirements

```
mcp>=1.0.0
```

## Running

```bash
pip install -r requirements.txt

# Run with a read-only token
MCP_BEARER_TOKEN=token-read-only python server.py

# Run with a read-write token
MCP_BEARER_TOKEN=token-read-write python server.py

# Run with an admin token
MCP_BEARER_TOKEN=token-admin python server.py

# Test expiry rejection
MCP_BEARER_TOKEN=token-expired python server.py
```

## Example MCP Client Configuration

```json
{
  "mcpServers": {
    "oauth-demo": {
      "command": "python",
      "args": ["/path/to/samples/05-oauth-mcp/server.py"],
      "env": {
        "MCP_BEARER_TOKEN": "token-read-write"
      }
    }
  }
}
```

## Scope-to-Tool Reference

```
data:read   → get_profile, list_resources
data:write  → create_resource
admin       → admin_status
```

## Testing Authorization Scenarios

| Scenario | Token to Use | Expected Result |
|----------|-------------|-----------------|
| Read profile | `token-read-only` | Success |
| Create resource with read-only token | `token-read-only` | Denied (scope) |
| Create resource with read-write token | `token-read-write` | Success |
| Access admin status without admin scope | `token-read-write` | Denied (scope) |
| Use expired token | `token-expired` | Denied (expired) |
| No token set | _(unset)_ | Denied (no token) |

## Production Guidance

### Replace the Token Store with OAuth Introspection

The `validate_token()` function in `server.py` is the single integration point. Replace the `TOKEN_STORE` dict lookup with a call to your authorization server's [RFC 7662](https://datatracker.ietf.org/doc/html/rfc7662) introspection endpoint:

```python
# Production implementation sketch (inside validate_token)
import httpx

response = httpx.post(
    "https://auth.example.com/oauth/introspect",
    data={"token": token},
    auth=(CLIENT_ID, CLIENT_SECRET),
    timeout=5.0,
)
info = response.json()

if not info.get("active"):
    raise AuthError("Authorization failed: invalid or expired token")

now = time.time()
if now >= info["exp"]:
    raise AuthError("Authorization failed: invalid or expired token")

if required_scope not in info.get("scope", "").split():
    raise AuthError(f"Authorization denied: token does not have required scope '{required_scope}'")
```

### Additional Production Recommendations

- **Token caching**: cache introspection responses with a short TTL (e.g., 30 seconds) to reduce latency; always re-check `exp` from the cached response.
- **Transport security**: the MCP stdio transport inherits OS-level process isolation; for network MCP, enforce TLS and validate server certificates.
- **Token revocation**: implement token revocation checking (RFC 7009) or use short-lived tokens with frequent rotation.
- **Audience validation**: verify the `aud` claim in the introspection response matches your server's identifier.
- **Logging**: ship audit logs to a centralised SIEM. The user identity in each log entry enables per-user activity monitoring.
