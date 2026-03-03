# Authentication Patterns for MCP Servers

Authentication answers: **who is calling this MCP server?**

Local (stdio) MCP servers inherit the OS security model — only the process that spawned them can communicate with them. Remote MCP servers must implement explicit authentication.

---

## Local (stdio) Servers

For stdio transport, authentication is handled by the OS:
- The MCP server is launched by the MCP host as a subprocess
- Communication is via stdin/stdout — no network exposure
- No additional authentication is typically needed

**Remaining concern:** If the MCP server is accessible by multiple local users or processes, consider OS-level controls (file permissions, user isolation).

---

## Remote Servers (HTTP + SSE)

Remote MCP servers require explicit authentication. The MCP specification recommends OAuth 2.0, but simpler patterns are appropriate depending on context.

---

## Pattern 1: OAuth 2.0 (Recommended for user-facing remote servers)

Best for MCP servers that access user data or act on behalf of individual users.

**Flow:**
```
MCP Host → Authorization Server → Access Token → MCP Server
```

**Implementation points:**
- Use the Authorization Code flow with PKCE for public clients
- Validate `aud` (audience) claim in the JWT — must match your MCP server
- Validate `exp`, `iss`, `sub` claims
- Scope tokens to only what the MCP server needs
- Implement token refresh; short-lived access tokens (15-60 min)

**Example token validation (Python):**
```python
import jwt
from jwt import PyJWKClient

def validate_token(token: str, expected_audience: str) -> dict:
    jwks_client = PyJWKClient(JWKS_URI)
    signing_key = jwks_client.get_signing_key_from_jwt(token)

    payload = jwt.decode(
        token,
        signing_key.key,
        algorithms=["RS256"],
        audience=expected_audience,
        options={"verify_exp": True}
    )
    return payload
```

---

## Pattern 2: API Keys (Appropriate for server-to-server or operator-controlled)

Best for MCP servers accessed by a controlled set of systems (not end users).

**Implementation:**
- Generate cryptographically random keys: `secrets.token_urlsafe(32)`
- Transmit only via HTTPS in the `Authorization: Bearer <key>` header — never in URLs
- Hash keys at rest (bcrypt or SHA-256): never store plaintext
- Associate each key with a specific client/identity for audit purposes
- Implement key rotation without downtime (support two active keys during rotation window)

**Example (Python FastAPI):**
```python
from fastapi import Security, HTTPException
from fastapi.security import HTTPAuthorizationCredentials, HTTPBearer
import hashlib
import hmac

security = HTTPBearer()

def verify_api_key(credentials: HTTPAuthorizationCredentials = Security(security)):
    provided = credentials.credentials
    provided_hash = hashlib.sha256(provided.encode()).digest()

    for stored_hash in VALID_KEY_HASHES:
        if hmac.compare_digest(provided_hash, stored_hash):
            return True

    raise HTTPException(status_code=401, detail="Invalid API key")
```

---

## Pattern 3: Mutual TLS (mTLS) (High-assurance environments)

Best for internal infrastructure where both sides are controlled.

- Client presents a certificate; server validates it against a trusted CA
- Server presents a certificate; client validates it
- Provides strong identity guarantees without shared secrets
- More operational overhead (certificate lifecycle management)

---

## Session Management

For stateful MCP connections:
- Issue short-lived session tokens after initial auth
- Bind sessions to a specific user/client identity
- Invalidate sessions on logout or after a defined idle timeout
- Reject tool calls on expired sessions immediately

---

## What NOT to Do

- Don't pass credentials via URL query parameters (logged in proxies, browser history)
- Don't use HTTP Basic Auth without TLS
- Don't hardcode credentials in MCP server code or configuration files
- Don't share a single API key across multiple MCP servers or clients
- Don't roll your own cryptography for token validation

---

## Authentication for MCP Hosts

The MCP host (client side) also has responsibilities:
- Store credentials securely (OS keychain, not plaintext files)
- Don't log credentials or tokens in debug output
- Validate server TLS certificates — reject invalid/self-signed certs in production
- Re-authenticate on session expiry rather than caching tokens indefinitely

---

## Related

- [Authorization & Least Privilege](authorization.md)
- [Secure Design Principles](secure-design.md)
- [Transport Security](secure-design.md#8-transport-security)
