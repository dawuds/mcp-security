# Secure MCP Design Principles

Security should be designed in from the start — not bolted on. These principles apply to anyone building an MCP server.

---

## 1. Principle of Least Privilege

Your MCP server should have access to exactly what it needs — nothing more.

**For filesystem access:**
- Define an explicit allowlist of directories the server can access
- Run the server process under a dedicated low-privilege OS user
- Use read-only mounts where writes aren't needed

**For API credentials:**
- Create scoped credentials (e.g., read-only API key if only reads are needed)
- Use separate credentials per MCP server — never share admin credentials
- Rotate credentials regularly

**For database access:**
- Grant SELECT-only if the server only needs to query
- Use separate DB users per server with minimal grants

---

## 2. Validate All Inputs

Never trust tool call arguments from the AI model. The model's inputs can be influenced by adversarial content.

- Validate types, formats, and ranges for every parameter
- Reject unexpected or extra parameters
- Sanitize file paths — resolve, normalize, then check against allowlist
- Validate URLs to prevent SSRF (block internal IP ranges, private CIDRs)
- Limit string lengths and array sizes to prevent resource exhaustion

See [Input Validation Guide](input-validation.md) for implementation patterns.

---

## 3. Sanitize All Outputs

Content returned to the AI model becomes part of its context and can influence subsequent behavior. Treat it like user-facing output.

- Strip or escape content that looks like system instructions (e.g., lines starting with `SYSTEM:`, `Assistant:`)
- Truncate large responses to what's needed — don't return entire databases
- Avoid returning sensitive metadata (internal paths, stack traces, credentials) in tool responses
- Clearly mark data boundaries in structured responses

---

## 4. Design for Auditability

Every tool call should leave a trace.

- Log: tool name, arguments, response summary, timestamp, session/user context
- Use structured logging (JSON) for machine-parseable audit trails
- Assign a unique ID to each tool call for correlation
- Log failures and errors with enough context to reconstruct what happened
- Do NOT log sensitive values (passwords, tokens) — redact them

See [Logging & Monitoring Guide](logging-monitoring.md).

---

## 5. Explicit Over Implicit

Be explicit about what your MCP server does and doesn't do.

**In tool schemas:**
- Define strict JSON schemas with `additionalProperties: false`
- Mark required fields explicitly
- Add clear, honest descriptions — don't embed hidden instructions

**In tool behavior:**
- Return clear error messages when inputs are invalid
- Return structured results, not freeform text that could be misinterpreted

---

## 6. Fail Secure

When something goes wrong, default to the safe state.

- On validation failure: reject the request, return an error, log it
- On unexpected errors: return a generic error, log the details server-side
- Never silently ignore errors and continue execution
- Don't expose internal state (stack traces, internal paths) in error responses

---

## 7. Separate Concerns

Don't build "god tools" that do too many things.

- One tool should do one thing
- Don't combine read and write operations in a single tool
- Separate administrative tools from user-facing tools
- If a tool performs writes/sends/deletes, it should be clearly named and described

This limits blast radius if a tool is abused via prompt injection — an attacker can't pivot from a read tool to a write operation.

---

## 8. Transport Security

For remote MCP servers:
- Enforce TLS 1.2+ — no exceptions
- Use valid, CA-signed certificates in production
- Implement authentication before allowing any tool access
- Apply rate limiting at the transport layer

For local (stdio) MCP servers:
- Be cautious about which processes can spawn the MCP server
- Avoid passing secrets via environment variables where possible (prefer OS keychain or secret managers)

---

## 9. Defense in Depth

Don't rely on a single control. Layer defenses:

```
User intent → AI model → MCP Host (consent gate) → MCP Server (auth + validation) → Backend system (least privilege)
```

Each layer should enforce its own security controls — don't assume an upstream layer has already validated inputs.

---

## 10. Review Tool Descriptions

Tool names and descriptions directly influence AI model behavior. Review them with the same care as security-sensitive code.

- Keep descriptions accurate and minimal
- Never embed instructions for the AI in tool descriptions
- Version-control tool schemas and alert on unexpected changes
- Periodically review whether exposed tools are still needed

---

## Secure MCP Server Checklist (Developer)

- [ ] Input schema defined with strict validation and `additionalProperties: false`
- [ ] All file paths validated against an allowlist
- [ ] All URLs validated to prevent SSRF
- [ ] Authentication implemented for remote servers
- [ ] Rate limiting implemented
- [ ] Structured audit logging for every tool call
- [ ] Server runs as dedicated low-privilege user
- [ ] Credentials are scoped to minimum permissions
- [ ] Error responses don't expose internal details
- [ ] Tool descriptions reviewed for accuracy and no hidden instructions
- [ ] Dependencies kept up to date

---

## Related

- [Authentication Patterns](authentication.md)
- [Authorization & Least Privilege](authorization.md)
- [Input Validation](input-validation.md)
- [Logging & Monitoring](logging-monitoring.md)
