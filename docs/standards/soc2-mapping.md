# SOC 2 Type II Mapping for MCP Security Controls

This document maps the [MCP Controls Framework](controls-framework.md) to SOC 2 Type II Trust Services Criteria (TSC). The mapping covers the system boundary of an MCP server deployment, including the MCP server process, its authentication layer, connected backends, transport security, and audit logging. Each criterion is mapped to the specific MCP controls that provide evidence of compliance, along with implementation notes relevant to MCP's architecture and threat model.

---

## CC6 — Logical and Physical Access Controls

| TSC ID | TSC Name | MCP Control | Implementation Notes |
|--------|----------|-------------|----------------------|
| CC6.1 | Logical access security measures restrict access to systems | IAM-1, IAM-2 | All remote MCP endpoints require authentication. Approved mechanisms are OAuth 2.0 with PKCE, API keys (stored hashed), and mTLS. Unauthenticated access returns HTTP 401. |
| CC6.2 | New user access provisioning is controlled | IAM-7, GOV-2 | MCP server credentials are provisioned through a controlled process with a designated owner. Credential issuance is logged and tied to an identity. |
| CC6.3 | Role of privileged access and separation of duties | IAM-5, IAM-7 | Tool-level authorization enforces least privilege per client. Administrative access (deployment, configuration) requires separate credentials and MFA; it is not available via the tool-call API surface. |
| CC6.6 | Transmission of data is protected | TLS-1, TLS-2, TLS-3 | All remote MCP connections use TLS 1.2+. Certificates are CA-signed and monitored for expiry. Weak cipher suites (RC4, 3DES, CBC-mode TLS 1.0/1.1) are disabled. |
| CC6.7 | Removal of access when no longer needed | IAM-4, IAM-6 | Credentials are rotated on a defined schedule and revoked immediately on personnel departure or suspected compromise. Each MCP server uses unique credentials; revoking one does not affect others. |
| CC6.8 | Unauthorized entities are prevented from accessing systems | IAM-1, IV-1, IV-5 | Schema validation and input size limits prevent malformed inputs from bypassing controls. Authentication is enforced at the transport layer before any tool call is processed. |

---

## CC7 — System Operations

| TSC ID | TSC Name | MCP Control | Implementation Notes |
|--------|----------|-------------|----------------------|
| CC7.1 | Detection and monitoring infrastructure is in place | AUD-1, AUD-2, AUD-6 | Every tool call is logged with: timestamp, session ID, tool name, caller identity, sanitized input summary, outcome, and duration. Authentication failures and authorization denials generate security events. Anomaly detection alerts are configured for unusual tool call patterns. |
| CC7.2 | Monitoring includes detection of anomalies | AUD-6, AUD-7 | Alerts are defined for: high call volumes, repeated auth failures, unusual tool sequences (e.g., read followed immediately by network exfiltration), and after-hours activity. Rate limiting constrains per-client call rates. |
| CC7.3 | Evaluated security events are communicated to appropriate parties | RES-3, AUD-4 | MCP security events are included in organizational incident response procedures. Logs are forwarded to centralized SIEM for correlation with other security events. |
| CC7.4 | Incidents are identified and responded to | RES-3, AUD-1 | MCP incidents follow defined response procedures. Audit logs provide the reconstruction capability required for incident investigation: what tools were called, when, by which session, with what inputs. |
| CC7.5 | Identified security incidents are contained, eradicated, and remediated | RES-3, IAM-4 | Containment procedures include immediate credential revocation for the affected MCP server and disconnection from the MCP host. Credentials the MCP server held access to are rotated as part of recovery. |

---

## CC8 — Change Management

| TSC ID | TSC Name | MCP Control | Implementation Notes |
|--------|----------|-------------|----------------------|
| CC8.1 | Changes to infrastructure, data, and software are authorized | GOV-3, CFG-5 | Tool schemas and descriptions are version-controlled in Git. Changes require PR review before merge. Dependencies are pinned; updates go through CI that runs security audits (`pip audit`, `npm audit`). |
| CC8.2 | Changes are tested prior to production deployment | GOV-3, IV-1 | Schema validation is run in CI. Tool definition changes are reviewed for embedded instructions or overly broad capabilities before merging. |
| CC8.3 | Emergency changes are authorized and documented | GOV-3 | Emergency changes to tool definitions or server configuration follow an expedited review process but still require documented authorization. Audit log of the change is retained. |
| CC8.4 | Confidential information is protected during migration | OUT-2, AUD-3 | Tool responses return only the fields needed for the task; credentials, tokens, and PII are excluded from logs. Data minimization applies during deployment changes as well as steady-state. |

---

## CC9 — Risk Mitigation

| TSC ID | TSC Name | MCP Control | Implementation Notes |
|--------|----------|-------------|----------------------|
| CC9.1 | Risks are identified, assessed, and mitigated | GOV-1, GOV-4 | An inventory of all MCP servers is maintained, including tools exposed, connected backends, and authentication method. Third-party MCP servers are vetted before connection; the vetting review covers tool definitions, source code, and data access requirements. |
| CC9.2 | Third-party vendors are assessed for risk | GOV-4 | Third-party MCP server vetting covers: source code review (or audit report), tool definition review for embedded instructions, permissions required, vendor security assessment, and contractual requirements. |
| CC9.3 | Risk management includes monitoring of identified risks | AUD-6, GOV-3 | Tool description integrity is monitored at startup: live tool definitions are compared against a stored hash of the approved state. Unexpected changes trigger an alert and prevent startup. |
| CC9.4 | Risk mitigation strategies include insurance coverage | — | Not MCP-specific. Handled at the organizational level through cyber insurance. |

---

## A1 — Availability

| TSC ID | TSC Name | MCP Control | Implementation Notes |
|--------|----------|-------------|----------------------|
| A1.1 | Capacity is managed | AUD-7, RES-1 | Rate limiting constrains per-client tool call rates, preventing resource exhaustion from runaway agentic loops. Tool execution timeouts prevent indefinite blocking. |
| A1.2 | Environmental protections, backup, and recovery | RES-1, RES-2 | Tool executions have timeouts. Graceful error handling prevents unexpected inputs from crashing the server. Infrastructure-level backup and recovery is handled outside the MCP controls framework. |
| A1.3 | Recovery testing is performed | RES-3 | MCP servers are included in disaster recovery testing. Failover procedures for MCP endpoints are documented in runbooks. |

---

## PI1 — Processing Integrity

| TSC ID | TSC Name | MCP Control | Implementation Notes |
|--------|----------|-------------|----------------------|
| PI1.1 | Inputs are complete and valid | IV-1, IV-2, IV-3, IV-4, IV-5 | All tool inputs are validated against strict JSON schemas with `additionalProperties: false`. Path inputs are validated against directory allowlists. URL inputs are checked for SSRF patterns. Injection sinks use parameterized queries and no shell interpolation. |
| PI1.2 | Outputs are complete and accurate | OUT-1, OUT-2, OUT-3 | Tool responses are sanitized before returning to the AI model. Only required fields are returned; internal paths, stack traces, and credentials are stripped. Error responses use generic messages to callers. |
| PI1.3 | Processing is timely | RES-1, AUD-7 | Tool execution timeouts prevent hanging operations. Rate limiting prevents individual sessions from monopolizing server capacity. |
| PI1.4 | Errors are identified and addressed | OUT-3, RES-2 | Error handling is graceful — invalid inputs and unexpected conditions are caught, logged server-side with detail, and returned to callers as generic error messages. |

---

## C1 — Confidentiality

| TSC ID | TSC Name | MCP Control | Implementation Notes |
|--------|----------|-------------|----------------------|
| C1.1 | Confidential information is identified and maintained | OUT-2, AUD-3 | Data minimization controls ensure tool responses include only what is needed for the task. Sensitive fields (credentials, tokens, PII beyond what was requested) are stripped from responses. Logs exclude credentials and tokens. |
| C1.2 | Confidential information is protected during disposal | AUD-3, OUT-2 | Session data and tool response buffers are not persisted beyond the session. Log retention policies specify both minimum and maximum retention periods. |

---

## Gaps and Considerations

SOC 2 TSC is a general-purpose controls framework. Several MCP-specific threats are not well-addressed by existing criteria:

**Prompt Injection** — SOC 2 has no criteria for AI-specific input manipulation. The risk that a tool returns malicious content that redirects AI model behavior is not captured by PI1 (which focuses on data processing integrity, not AI inference manipulation). Organizations should document prompt injection risk in their risk register and describe compensating controls (output sanitization, tool call policies, user confirmation gates).

**Tool Poisoning** — The risk that an MCP server's tool descriptions are crafted to manipulate AI behavior falls between CC9.2 (third-party risk) and CC8.1 (change management), but neither criterion was written with AI tool discovery in mind. GOV-3 and GOV-4 controls address this gap; auditors should request evidence of tool description integrity checking and third-party vetting specifically for MCP servers.

**Confused Deputy / Indirect Injection** — SOC 2 does not address the scenario where an AI model is manipulated into taking actions the user didn't authorize using the MCP server's credentials. This is a design-level risk that requires compensating controls (tool segmentation, user confirmation gates for write/send/delete) documented in the system description.

**AI Model Behavior** — The AI model itself is typically a third-party service (e.g., Anthropic's Claude). Its behavior under adversarial inputs is outside the SOC 2 boundary of the MCP server. Organizations should document this dependency in their system description and vendor risk register.

---

## Related

- [Controls Framework](controls-framework.md)
- [NIST Mapping](nist-mapping.md)
- [ISO 27001 Mapping](iso27001-mapping.md)
- [Audit Checklist](../audit/audit-checklist.md)
- [MCP in the Enterprise](../../discussions/topics/mcp-in-enterprise.md)
