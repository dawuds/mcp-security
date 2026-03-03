# MCP Security Controls Framework

A controls framework purpose-built for MCP server deployments. Organized by control domain, each control includes an objective, rationale, implementation guidance, and test method.

---

## Framework Overview

This framework defines **44 controls** across **8 domains** for securing MCP deployments. Controls are assigned a maturity tier:

| Tier | Label | Description |
|------|-------|-------------|
| 1 | **Foundational** | Minimum viable security — implement for all MCP servers |
| 2 | **Standard** | Expected for production deployments |
| 3 | **Advanced** | For high-assurance or regulated environments |

---

## Domain 1: Governance (GOV)

### GOV-1: MCP Server Inventory (Tier 1)
**Objective:** Maintain an accurate inventory of all MCP servers.

**Rationale:** You can't secure what you don't know exists. Shadow MCP servers create unmanaged risk.

**Implementation:** Maintain a register including: server name, owner, tools exposed, connected backends, authentication method, deployment date, last reviewed.

**Test:** Compare actual running MCP processes to inventory. Identify gaps.

---

### GOV-2: Ownership Assignment (Tier 1)
**Objective:** Every MCP server has a designated security owner.

**Rationale:** Assigns accountability for security decisions and incidents.

**Implementation:** Record owner in inventory. Include in runbooks and incident response procedures.

---

### GOV-3: Tool Definition Change Control (Tier 2)
**Objective:** Tool schemas and descriptions are version-controlled and changes are reviewed.

**Rationale:** Unauthorized changes to tool descriptions could introduce tool poisoning.

**Implementation:** Store tool definitions in Git. Require PR review before merging changes. Alert on unexpected diffs.

---

### GOV-4: Third-Party MCP Server Vetting (Tier 2)
**Objective:** Third-party MCP servers are reviewed before connection.

**Rationale:** Connecting to an unvetted MCP server is equivalent to running untrusted code with AI model access.

**Implementation:** Review process covering: tool definitions, source code (if available), permissions required, data accessed, vendor trust assessment.

---

## Domain 2: Identity and Access Management (IAM)

### IAM-1: Authentication Required (Tier 1)
**Objective:** All remote MCP endpoints require authentication.

**Implementation:** See [Authentication Patterns](../build/authentication.md).

**Test:** Attempt to call any tool without credentials. Expect 401.

---

### IAM-2: Approved Authentication Mechanisms (Tier 1)
**Objective:** Authentication uses approved, strong mechanisms.

**Approved:** OAuth 2.0 with PKCE, API keys (securely generated and stored), mTLS.

**Not approved:** HTTP Basic Auth, shared secrets in URLs, no auth.

---

### IAM-3: Credential Security (Tier 1)
**Objective:** Credentials are stored and transmitted securely.

**Requirements:**
- Stored hashed (API keys) or in secrets manager
- Transmitted only over TLS in Authorization header
- Not committed to source code or configuration files

---

### IAM-4: Credential Rotation (Tier 2)
**Objective:** Credentials are rotated on a defined schedule.

**Implementation:** API keys rotated at least annually, or immediately on suspected compromise. Support two-key rotation to avoid downtime.

---

### IAM-5: Least Privilege Access (Tier 1)
**Objective:** Each MCP client is granted access to only the tools and resources it needs.

**Implementation:** Define per-client tool access lists. Implement tool-level authorization. See [Authorization Guide](../build/authorization.md).

---

### IAM-6: Unique Credentials Per Server (Tier 1)
**Objective:** Each MCP server has unique credentials; no shared credentials.

**Rationale:** Shared credentials mean a compromise of one server compromises all.

---

### IAM-7: Privileged Access Control (Tier 2)
**Objective:** Access to MCP server administration (deployment, configuration) is restricted to authorized personnel.

**Implementation:** Separate admin access from tool-call access. Require MFA for admin access.

---

## Domain 3: Secure Configuration (CFG)

### CFG-1: Least Privilege OS Account (Tier 1)
**Objective:** MCP server processes run as dedicated low-privilege OS users, not root.

**Implementation:** Create a dedicated service account. Apply AppArmor/seccomp profiles.

**Test:** Check running process user: `ps aux | grep mcp_server`

---

### CFG-2: Filesystem Permission Hardening (Tier 1)
**Objective:** MCP server file access is restricted to required paths only.

**Implementation:** Set restrictive file permissions. Use mount namespaces or chroot if feasible.

---

### CFG-3: API/Service Credential Scoping (Tier 1)
**Objective:** API and database credentials used by MCP servers are scoped to minimum required permissions.

**Implementation:** Create service accounts with minimal grants. No admin credentials for read-only tools.

---

### CFG-4: Minimal Tool Surface (Tier 2)
**Objective:** Only tools required by current use cases are exposed.

**Implementation:** Audit exposed tools quarterly. Remove unused tools. Apply tool access controls rather than exposing all tools to all clients.

---

### CFG-5: Dependency Management (Tier 2)
**Objective:** MCP server dependencies are pinned, current, and free of known vulnerabilities.

**Implementation:** Pin versions in requirements.txt / package-lock.json. Run `pip audit` / `npm audit` in CI. Apply security updates promptly.

---

## Domain 4: Input Validation (IV)

### IV-1: Schema Validation (Tier 1)
**Objective:** All tool inputs are validated against strict JSON schemas.

**Requirements:** `additionalProperties: false`; required fields defined; types, formats, and ranges specified.

---

### IV-2: Path Validation (Tier 1)
**Objective:** File path inputs cannot be used for path traversal.

**Requirements:** Resolve to real path; validate against allowlist of directories; reject traversal sequences.

---

### IV-3: SSRF Prevention (Tier 1)
**Objective:** URL inputs cannot be used for SSRF.

**Requirements:** Allowlist schemes; block private IP ranges; resolve DNS before fetching (rebinding protection).

---

### IV-4: Injection Prevention (Tier 1)
**Objective:** Inputs cannot be used for SQL, shell, or template injection.

**Requirements:** Parameterized queries; no `shell=True` in subprocess; no user input in format strings.

---

### IV-5: Input Size Limits (Tier 1)
**Objective:** Inputs are bounded to prevent resource exhaustion.

**Requirements:** Maximum string length; maximum array/collection size; maximum file size for read operations.

---

## Domain 5: Output Handling (OUT)

### OUT-1: Response Sanitization (Tier 2)
**Objective:** Content returned to the AI model is sanitized to reduce prompt injection risk.

**Implementation:** Truncate to reasonable limits; wrap in clear data delimiters; strip content that looks like instructions.

---

### OUT-2: Sensitive Data Minimization (Tier 1)
**Objective:** Tool responses do not include sensitive data beyond what was requested.

**Implementation:** Return only fields the AI model needs. Don't include internal paths, full stack traces, or credentials in responses.

---

### OUT-3: Error Response Hardening (Tier 1)
**Objective:** Error responses don't expose internal implementation details.

**Implementation:** Generic error messages to callers; detailed errors in server-side logs only.

---

## Domain 6: Transport Security (TLS)

### TLS-1: Enforce TLS (Tier 1)
**Objective:** All remote MCP communication is encrypted with TLS 1.2+.

---

### TLS-2: Certificate Validity (Tier 1)
**Objective:** TLS certificates are valid, CA-signed, and not expired.

---

### TLS-3: Cipher Suite Hardening (Tier 2)
**Objective:** Weak cipher suites and deprecated TLS versions are disabled.

---

## Domain 7: Audit and Monitoring (AUD)

### AUD-1: Tool Call Logging (Tier 1)
**Objective:** Every tool call is logged with required fields.

**Required fields:** timestamp, session ID, call ID, tool name, caller identity, input summary (sanitized), outcome, duration.

---

### AUD-2: Security Event Logging (Tier 1)
**Objective:** Authentication failures, authorization denials, and validation failures are logged.

---

### AUD-3: Sensitive Data Exclusion (Tier 1)
**Objective:** Credentials, tokens, and PII are not logged.

---

### AUD-4: Centralized Log Collection (Tier 2)
**Objective:** Logs are forwarded to a centralized logging or SIEM system.

---

### AUD-5: Log Retention (Tier 2)
**Objective:** Logs are retained according to policy and applicable regulatory requirements.

---

### AUD-6: Anomaly Detection (Tier 3)
**Objective:** Alerts are configured for anomalous MCP tool call patterns.

**Implement alerts for:** high call volumes, repeated auth failures, unusual tool sequences, after-hours activity.

---

### AUD-7: Rate Limiting (Tier 2)
**Objective:** Tool calls are rate-limited per client/session to prevent abuse.

---

## Domain 8: Resilience and Response (RES)

### RES-1: Tool Execution Timeouts (Tier 2)
**Objective:** Tool executions have timeouts to prevent indefinite hanging.

---

### RES-2: Graceful Error Handling (Tier 1)
**Objective:** Invalid or unexpected inputs do not cause server crashes.

---

### RES-3: MCP in Incident Response Procedures (Tier 2)
**Objective:** MCP security events are included in organizational incident response procedures.

---

## Controls Summary Table

| ID | Control | Tier | Domain |
|----|---------|------|--------|
| GOV-1 | MCP Server Inventory | 1 | Governance |
| GOV-2 | Ownership Assignment | 1 | Governance |
| GOV-3 | Tool Definition Change Control | 2 | Governance |
| GOV-4 | Third-Party Vetting | 2 | Governance |
| IAM-1 | Authentication Required | 1 | IAM |
| IAM-2 | Approved Auth Mechanisms | 1 | IAM |
| IAM-3 | Credential Security | 1 | IAM |
| IAM-4 | Credential Rotation | 2 | IAM |
| IAM-5 | Least Privilege Access | 1 | IAM |
| IAM-6 | Unique Credentials | 1 | IAM |
| IAM-7 | Privileged Access Control | 2 | IAM |
| CFG-1 | Least Privilege OS Account | 1 | Configuration |
| CFG-2 | Filesystem Permission Hardening | 1 | Configuration |
| CFG-3 | API Credential Scoping | 1 | Configuration |
| CFG-4 | Minimal Tool Surface | 2 | Configuration |
| CFG-5 | Dependency Management | 2 | Configuration |
| IV-1 | Schema Validation | 1 | Input Validation |
| IV-2 | Path Validation | 1 | Input Validation |
| IV-3 | SSRF Prevention | 1 | Input Validation |
| IV-4 | Injection Prevention | 1 | Input Validation |
| IV-5 | Input Size Limits | 1 | Input Validation |
| OUT-1 | Response Sanitization | 2 | Output |
| OUT-2 | Sensitive Data Minimization | 1 | Output |
| OUT-3 | Error Response Hardening | 1 | Output |
| TLS-1 | Enforce TLS | 1 | Transport |
| TLS-2 | Certificate Validity | 1 | Transport |
| TLS-3 | Cipher Suite Hardening | 2 | Transport |
| AUD-1 | Tool Call Logging | 1 | Audit |
| AUD-2 | Security Event Logging | 1 | Audit |
| AUD-3 | Sensitive Data Exclusion | 1 | Audit |
| AUD-4 | Centralized Log Collection | 2 | Audit |
| AUD-5 | Log Retention | 2 | Audit |
| AUD-6 | Anomaly Detection | 3 | Audit |
| AUD-7 | Rate Limiting | 2 | Audit |
| RES-1 | Tool Execution Timeouts | 2 | Resilience |
| RES-2 | Graceful Error Handling | 1 | Resilience |
| RES-3 | MCP in Incident Response | 2 | Resilience |

---

## Related

- [NIST Mapping](nist-mapping.md)
- [Audit Checklist](../audit/audit-checklist.md)
- [Secure Design Principles](../build/secure-design.md)
