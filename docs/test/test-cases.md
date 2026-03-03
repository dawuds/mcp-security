# MCP Security Test Cases

Structured test cases for MCP server security testing. Each case includes the test objective, inputs, expected result, and fail condition.

---

## TC-AUTH: Authentication

### TC-AUTH-01: No Credentials

**Tool:** Any authenticated endpoint
**Input:** Request with no `Authorization` header
**Expected:** 401 Unauthorized
**Fail:** Tool executes or data is returned

### TC-AUTH-02: Expired Token

**Tool:** Any authenticated endpoint
**Input:** Valid JWT with `exp` timestamp in the past
**Expected:** 401 Unauthorized
**Fail:** Tool executes

### TC-AUTH-03: Invalid Signature

**Tool:** Any authenticated endpoint
**Input:** JWT with tampered payload and original signature
**Expected:** 401 Unauthorized
**Fail:** Tool executes

### TC-AUTH-04: Algorithm Confusion (alg=none)

**Tool:** Any JWT-authenticated endpoint
**Input:** JWT with `"alg": "none"` and no signature
**Expected:** 401 Unauthorized
**Fail:** Tool executes

### TC-AUTH-05: Wrong Audience

**Tool:** Any authenticated endpoint
**Input:** Valid JWT with `aud` set to a different service
**Expected:** 401 Unauthorized
**Fail:** Tool executes

---

## TC-AUTHZ: Authorization

### TC-AUTHZ-01: Horizontal Privilege Escalation

**Tool:** Any user-scoped tool (e.g., `read_file`)
**Input:** Valid token for User A; path/resource belonging to User B
**Expected:** 403 Forbidden
**Fail:** User B's data is returned

### TC-AUTHZ-02: Vertical Privilege Escalation

**Tool:** Admin-restricted tool (e.g., `reload_config`)
**Input:** Valid token for standard (non-admin) user
**Expected:** 403 Forbidden
**Fail:** Tool executes

### TC-AUTHZ-03: Write Tool with Read-Only Token

**Tool:** Any write tool (e.g., `write_file`)
**Input:** Valid token scoped to read-only
**Expected:** 403 Forbidden
**Fail:** Write executes

---

## TC-IV: Input Validation

### TC-IV-01: Path Traversal — Relative

**Tool:** `read_file` or any path-accepting tool
**Inputs to test:**
- `../../etc/passwd`
- `../../../etc/shadow`
- `....//....//etc/passwd`
**Expected:** Error (path not allowed)
**Fail:** File content returned

### TC-IV-02: Path Traversal — Absolute

**Tool:** `read_file` or any path-accepting tool
**Inputs to test:**
- `/etc/passwd`
- `/root/.ssh/id_rsa`
- `/proc/self/environ`
**Expected:** Error (path not allowed)
**Fail:** File content returned

### TC-IV-03: Path Traversal — URL-Encoded

**Tool:** `read_file` or any path-accepting tool
**Inputs to test:**
- `%2e%2e%2f%2e%2e%2fetc%2fpasswd`
- `..%2F..%2Fetc%2Fpasswd`
**Expected:** Error (path not allowed)
**Fail:** File content returned

### TC-IV-04: SSRF — Cloud Metadata

**Tool:** Any URL-fetching tool
**Inputs to test:**
- `http://169.254.169.254/latest/meta-data/`
- `http://metadata.google.internal/computeMetadata/v1/`
- `http://100.100.100.200/latest/meta-data/`
**Expected:** Error (URL not allowed)
**Fail:** Response from metadata endpoint returned

### TC-IV-05: SSRF — Internal Services

**Tool:** Any URL-fetching tool
**Inputs to test:**
- `http://localhost:6379` (Redis)
- `http://10.0.0.1:8080/admin`
- `http://192.168.1.1`
- `http://[::1]/`
**Expected:** Error (URL not allowed)
**Fail:** Response returned

### TC-IV-06: SSRF — Scheme Confusion

**Tool:** Any URL-fetching tool
**Inputs to test:**
- `file:///etc/passwd`
- `dict://localhost:11211/stat`
- `gopher://localhost/...`
**Expected:** Error (scheme not allowed)
**Fail:** Response returned

### TC-IV-07: SQL Injection

**Tool:** Any database-querying tool
**Inputs to test:**
- `' OR '1'='1`
- `'; DROP TABLE users; --`
- `1 UNION SELECT password FROM users`
**Expected:** Error or no data; no SQL error exposed; no extra data returned
**Fail:** SQL error message, extra rows, or data exfiltration

### TC-IV-08: Shell Injection

**Tool:** Any tool that runs system commands
**Inputs to test:**
- `test; cat /etc/passwd`
- `test && whoami`
- `` `id` ``
- `$(cat /etc/passwd)`
**Expected:** Error or only the intended output (no command execution)
**Fail:** Output includes results of injected commands

### TC-IV-09: Oversized Input

**Tool:** Any tool
**Inputs to test:**
- String of 1,000,000 characters
- Array of 100,000 items
- Deeply nested JSON (1000 levels)
**Expected:** Error (input too large)
**Fail:** Server hangs, crashes, or takes >30 seconds

### TC-IV-10: Extra Parameters

**Tool:** Any tool
**Input:** Valid required parameters + additional undeclared parameters
**Expected:** Error (validation failure) or parameters silently ignored with no side effects
**Fail:** Extra parameters cause unexpected behavior

### TC-IV-11: Missing Required Parameters

**Tool:** Any tool with required parameters
**Input:** Tool call with no arguments, or missing required fields
**Expected:** Clear error message
**Fail:** Server crashes or returns 500

---

## TC-TLS: Transport Security

### TC-TLS-01: HTTP Access

**Target:** Remote MCP server HTTP endpoint
**Expected:** Redirect to HTTPS or connection refused
**Fail:** MCP server accessible over plain HTTP

### TC-TLS-02: TLS Version

**Target:** Remote MCP server TLS configuration
**Test:** Attempt connection with TLS 1.0, TLS 1.1
**Expected:** Connection refused
**Fail:** TLS 1.0/1.1 connection succeeds

### TC-TLS-03: Certificate Validity

**Target:** Remote MCP server TLS certificate
**Check:** Expiry, CA trust chain, CN/SAN match
**Expected:** Valid, unexpired, trusted certificate
**Fail:** Self-signed, expired, or mismatched certificate in production

---

## TC-RL: Rate Limiting

### TC-RL-01: Rapid Tool Call Flooding

**Tool:** Any tool
**Input:** 1000 calls in 10 seconds
**Expected:** Rate limiting kicks in; 429 Too Many Requests or connection throttled
**Fail:** All 1000 calls execute

### TC-RL-02: Large Result Sets

**Tool:** Any tool that returns lists/collections
**Input:** Query that would return 1,000,000 results
**Expected:** Results are capped at the configured limit
**Fail:** Full result set returned or server OOM

---

## TC-LOG: Logging Verification

### TC-LOG-01: Tool Call Logged

**Action:** Call any tool successfully
**Verify:** Audit log contains entry with tool name, timestamp, caller identity
**Fail:** No log entry found

### TC-LOG-02: Failed Call Logged

**Action:** Call a tool that fails validation
**Verify:** Audit log contains failure entry with reason
**Fail:** No log entry for failed calls

### TC-LOG-03: No Secrets in Logs

**Action:** Call a tool with a credential-like parameter name
**Verify:** Log entry does not contain the credential value
**Fail:** Credential logged in plaintext

---

## Related

- [Testing Methodology](testing-methodology.md)
- [Prompt Injection Tests](prompt-injection-tests.md)
- [Assessment Checklist](../assess/assessment-checklist.md)
