# MCP Security Assessment Checklist

Use this checklist when assessing an MCP server or MCP-enabled deployment.

**Rating scale:** Pass / Fail / Partial / N/A

---

## 1. Discovery

- [ ] All exposed tools have been enumerated (`tools/list`)
- [ ] All exposed resources have been enumerated (`resources/list`)
- [ ] All exposed prompts have been enumerated (`prompts/list`)
- [ ] Tool descriptions have been reviewed for accuracy and embedded instructions
- [ ] MCP server version and dependencies have been identified
- [ ] Server-side OS/container configuration has been reviewed

---

## 2. Authentication

- [ ] The MCP endpoint requires authentication
- [ ] Unauthenticated access returns 401/403 (not 200 or 500)
- [ ] Expired tokens are rejected
- [ ] Tokens from other audiences/issuers are rejected
- [ ] JWT algorithm confusion attacks are not possible (alg=none rejected)
- [ ] API keys are hashed at rest (not stored in plaintext)
- [ ] Credentials are not passed in URL query parameters
- [ ] No hardcoded credentials in source code or configuration

---

## 3. Authorization

- [ ] Tool-level access controls are implemented
- [ ] Restricted tools cannot be called with standard credentials
- [ ] Horizontal privilege escalation is not possible (User A cannot access User B's resources)
- [ ] Admin tools are restricted to admin-level credentials
- [ ] Write/delete operations require elevated authorization or user confirmation

---

## 4. Input Validation

- [ ] All tool inputs are validated against a defined schema
- [ ] Schemas use `additionalProperties: false`
- [ ] File paths are validated and restricted to an allowlist of directories
- [ ] Absolute paths and `..` sequences are rejected for file path inputs
- [ ] Symlinks are resolved before path validation (using `realpath`)
- [ ] URLs are validated for scheme, host, and private IP ranges (SSRF prevention)
- [ ] Shell commands are constructed without user-controlled shell interpolation
- [ ] SQL queries use parameterized queries, not string formatting
- [ ] Input string lengths are bounded
- [ ] Array sizes are bounded

---

## 5. Output / Response Handling

- [ ] Tool outputs are sanitized before returning to AI model context
- [ ] Large outputs are truncated to reasonable limits
- [ ] Internal file paths are not exposed in error messages
- [ ] Stack traces are not included in tool call responses
- [ ] Credentials/tokens are not returned in tool outputs

---

## 6. Transport Security (Remote Servers)

- [ ] TLS 1.2 or higher is enforced
- [ ] TLS 1.0 and 1.1 are disabled
- [ ] HTTP (non-TLS) access is disabled or redirects to HTTPS
- [ ] Certificate is valid, CA-signed, and not expired
- [ ] Weak cipher suites are disabled (RC4, DES, 3DES, EXPORT)
- [ ] HSTS header is present

---

## 7. Least Privilege

- [ ] MCP server runs as a dedicated low-privilege OS user (not root)
- [ ] MCP server only has read access to filesystem paths it needs read access to
- [ ] MCP server credentials are scoped to minimum required API/DB permissions
- [ ] Each MCP server has its own credentials (no shared admin credentials)
- [ ] Unnecessary tools are not exposed

---

## 8. Audit Logging

- [ ] Every tool call is logged with: timestamp, tool name, caller identity, inputs (sanitized)
- [ ] Authorization failures are logged
- [ ] Log entries include a unique call/session identifier for correlation
- [ ] Credentials and sensitive values are not logged
- [ ] Logs are forwarded to a centralized system (SIEM/log management)
- [ ] Log retention meets compliance requirements

---

## 9. Rate Limiting and Resilience

- [ ] Rate limiting is implemented per client/session
- [ ] Repeated failures trigger alerts or temporary lockout
- [ ] Tool execution has timeouts to prevent hanging calls
- [ ] The server handles malformed inputs gracefully (no crash/panic)

---

## 10. Tool Design

- [ ] Each tool has a single, clearly defined purpose
- [ ] Tool names and descriptions accurately describe behavior
- [ ] No hidden instructions embedded in tool descriptions
- [ ] Tool schemas are version-controlled
- [ ] Destructive/write tools are clearly labeled as such
- [ ] Tool descriptions are reviewed periodically

---

## 11. Prompt Injection Resistance

- [ ] Tool outputs are not returned verbatim to the AI model without sanitization
- [ ] Data from external sources (web, email, files) is treated as untrusted
- [ ] The system prompt includes instructions to treat tool output as data, not instructions
- [ ] High-impact tool calls require user confirmation before execution

---

## 12. Dependency and Supply Chain

- [ ] MCP server dependencies are pinned to specific versions
- [ ] Dependencies have been reviewed for known vulnerabilities (pip audit, npm audit)
- [ ] The MCP SDK version in use is current and supported
- [ ] Third-party MCP servers (if used) have been reviewed and vetted

---

## Summary Scorecard

| Category | Pass | Fail | Partial | N/A |
|----------|------|------|---------|-----|
| Discovery | | | | |
| Authentication | | | | |
| Authorization | | | | |
| Input Validation | | | | |
| Output Handling | | | | |
| Transport Security | | | | |
| Least Privilege | | | | |
| Audit Logging | | | | |
| Rate Limiting | | | | |
| Tool Design | | | | |
| Prompt Injection | | | | |
| Supply Chain | | | | |

---

## Related

- [Assessment Methodology](assessment-methodology.md)
- [Audit Checklist](../audit/audit-checklist.md)
- [Threat Model](../03-threat-model.md)
