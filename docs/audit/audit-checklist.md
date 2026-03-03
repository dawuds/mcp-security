# MCP Audit Checklist

Evidence-based control checklist for auditing MCP server deployments. For each control, note: status (Implemented / Partial / Not Implemented / N/A), evidence reference, and finding if applicable.

---

## Control Domain 1: Governance and Inventory

| Control ID | Control Statement | Evidence | Status | Finding |
|-----------|-----------------|----------|--------|---------|
| GOV-1 | An inventory of all MCP servers is maintained and kept current | MCP server inventory register | | |
| GOV-2 | Each MCP server has a designated owner responsible for its security | Ownership assignments | | |
| GOV-3 | A process exists for approving new MCP server deployments | Approval process documentation | | |
| GOV-4 | Tool definitions (schemas) are version-controlled | Git history or equivalent | | |
| GOV-5 | Tool definitions are reviewed before deployment | Review records | | |
| GOV-6 | A process exists for retiring or decommissioning MCP servers | Decommission process documentation | | |

---

## Control Domain 2: Access Control

| Control ID | Control Statement | Evidence | Status | Finding |
|-----------|-----------------|----------|--------|---------|
| AC-1 | All remote MCP server endpoints require authentication | Configuration evidence, test results | | |
| AC-2 | Authentication uses an approved mechanism (OAuth 2.0, API key with hashing) | Authentication implementation review | | |
| AC-3 | Credentials are stored securely (hashed, not plaintext) | Credential store review | | |
| AC-4 | Credential rotation is performed on a defined schedule | Rotation logs or policy | | |
| AC-5 | Tool-level access controls restrict sensitive tools to authorized callers | Authorization configuration review | | |
| AC-6 | Each MCP server has unique credentials (no shared credentials) | Credential inventory | | |
| AC-7 | Administrative access to MCP server configuration is restricted | Access control list | | |

---

## Control Domain 3: Secure Configuration

| Control ID | Control Statement | Evidence | Status | Finding |
|-----------|-----------------|----------|--------|---------|
| SC-1 | MCP server processes run as dedicated low-privilege OS users (not root) | Process listing, user configuration | | |
| SC-2 | OS-level file permissions restrict MCP server access to required paths only | File system permission review | | |
| SC-3 | MCP server API/DB credentials are scoped to minimum required permissions | Credential scope review | | |
| SC-4 | Unnecessary tools are not exposed (principle of least functionality) | Tool inventory vs. requirements | | |
| SC-5 | MCP server dependencies are pinned to specific versions | requirements.txt / package-lock review | | |
| SC-6 | Dependencies are regularly scanned for known vulnerabilities | Scan results | | |

---

## Control Domain 4: Transport Security

| Control ID | Control Statement | Evidence | Status | Finding |
|-----------|-----------------|----------|--------|---------|
| TS-1 | Remote MCP servers enforce TLS 1.2 or higher | TLS configuration or scan result | | |
| TS-2 | TLS 1.0 and 1.1 are disabled | TLS configuration | | |
| TS-3 | Certificates are valid, CA-signed, and not expired | Certificate inspection | | |
| TS-4 | HTTP (non-TLS) access is disabled or redirects to HTTPS | Configuration or test result | | |
| TS-5 | Weak cipher suites are disabled | TLS scan result (testssl.sh or equivalent) | | |

---

## Control Domain 5: Input Validation

| Control ID | Control Statement | Evidence | Status | Finding |
|-----------|-----------------|----------|--------|---------|
| IV-1 | All tool inputs are validated against defined schemas | Code review or documentation | | |
| IV-2 | File path inputs are restricted to allowlisted directories | Implementation review | | |
| IV-3 | URL inputs are validated to prevent SSRF | Implementation review | | |
| IV-4 | Database queries use parameterized queries | Code review | | |
| IV-5 | Input size limits are enforced to prevent resource exhaustion | Implementation review | | |

---

## Control Domain 6: Audit Logging

| Control ID | Control Statement | Evidence | Status | Finding |
|-----------|-----------------|----------|--------|---------|
| AL-1 | Audit logging is enabled for all tool calls | Logging configuration | | |
| AL-2 | Logs include required fields: timestamp, tool, caller identity, outcome | Log sample review | | |
| AL-3 | Logs include unique call identifiers for correlation | Log sample review | | |
| AL-4 | Sensitive values (credentials, PII) are excluded from logs | Log sample review | | |
| AL-5 | Logs are forwarded to a centralized logging/SIEM system | Log forwarding configuration | | |
| AL-6 | Log retention meets policy/compliance requirements | Retention policy and configuration | | |
| AL-7 | Log integrity is protected (logs cannot be modified by the MCP server user) | Log storage configuration | | |

---

## Control Domain 7: Monitoring and Response

| Control ID | Control Statement | Evidence | Status | Finding |
|-----------|-----------------|----------|--------|---------|
| MR-1 | Alerts are configured for repeated authentication/authorization failures | Alert configuration | | |
| MR-2 | Alerts are configured for anomalous tool call volumes | Alert configuration | | |
| MR-3 | MCP security events are included in incident response procedures | IR documentation | | |
| MR-4 | Rate limiting is implemented per client/session | Implementation review | | |

---

## Control Domain 8: Third-Party MCP Servers

| Control ID | Control Statement | Evidence | Status | Finding |
|-----------|-----------------|----------|--------|---------|
| TP-1 | A process exists for reviewing and approving third-party MCP servers | Vetting process documentation | | |
| TP-2 | Third-party MCP server tool definitions are reviewed before connection | Review records | | |
| TP-3 | Third-party MCP servers are treated with reduced trust relative to first-party | Architecture documentation | | |
| TP-4 | The list of connected third-party MCP servers is inventoried and reviewed periodically | Inventory | | |

---

## Audit Summary

| Domain | Controls | Implemented | Partial | Not Implemented | N/A |
|--------|----------|-------------|---------|----------------|-----|
| Governance | 6 | | | | |
| Access Control | 7 | | | | |
| Secure Configuration | 6 | | | | |
| Transport Security | 5 | | | | |
| Input Validation | 5 | | | | |
| Audit Logging | 7 | | | | |
| Monitoring & Response | 4 | | | | |
| Third-Party MCP | 4 | | | | |
| **Total** | **44** | | | | |

---

## Related

- [Audit Methodology](audit-methodology.md)
- [Assessment Checklist](../assess/assessment-checklist.md)
- [Controls Framework](../standards/controls-framework.md)
