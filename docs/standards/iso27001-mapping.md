# ISO 27001:2022 Annex A Mapping for MCP Security Controls

This document maps the [MCP Controls Framework](controls-framework.md) to ISO/IEC 27001:2022 Annex A controls. The mapping covers the information security controls applicable to MCP server deployments across the full lifecycle: development, deployment, operation, and decommission. Where an Annex A control is directly satisfied by an MCP control, the implementation details are MCP-specific. Where multiple MCP controls together satisfy a single Annex A control, all are listed.

---

## Annex A Control Mapping

| Annex A ID | Control Name | MCP Implementation | Notes |
|------------|--------------|-------------------|-------|
| A.5.1 | Policies for information security | GOV-2, RES-3 | Each MCP server has a designated security owner (GOV-2). MCP security events are covered in organizational incident response procedures (RES-3). Security policy documents should explicitly include MCP servers in scope. |
| A.5.10 | Acceptable use of information and other associated assets | GOV-1, IAM-5 | The MCP server inventory (GOV-1) defines what data each server is authorized to access. Tool-level least privilege (IAM-5) enforces that AI clients access only what's needed for the specific task. |
| A.5.14 | Information transfer | TLS-1, TLS-2, TLS-3, OUT-2 | All data transferred over remote MCP transports is encrypted with TLS 1.2+. Tool responses return only the minimum data required (OUT-2), limiting exposure during transfer. |
| A.5.15 | Access control | IAM-1, IAM-2, IAM-5 | Remote MCP endpoints require authentication using approved mechanisms (OAuth 2.0, API keys, mTLS). Tool-level authorization enforces per-client access lists. See [Authentication Patterns](../build/authentication.md) and [Authorization Guide](../build/authorization.md). |
| A.5.23 | Information security for use of cloud services | GOV-4, IAM-3 | Third-party MCP servers (cloud-hosted or SaaS) are vetted before connection. Vetting covers tool definitions, data access scope, and vendor security posture. Credentials used to access cloud backends are scoped to minimum required permissions (IAM-3). |
| A.6.3 | Information security awareness, education and training | GOV-2 | Security owners for MCP servers are trained on MCP-specific threat scenarios (prompt injection, tool poisoning, confused deputy). Training materials should include this repository's documentation. |
| A.6.6 | Confidentiality or non-disclosure agreements | GOV-4 | Third-party MCP server operators should have appropriate data processing agreements in place, covering the data accessed through MCP tools and breach notification obligations. |
| A.8.2 | Privileged access rights | IAM-5, IAM-7, CFG-1 | Privileged access to MCP server administration is restricted and requires MFA. MCP servers run as dedicated low-privilege OS accounts (CFG-1). Tool-level access lists prevent privilege escalation via the tool API (IAM-5). |
| A.8.3 | Information access restriction | IAM-5, CFG-3, CFG-4 | AI clients are granted access to only the tools they need (IAM-5). Backend credentials are scoped to minimum permissions (CFG-3). Unused tools are removed or access-restricted rather than left available (CFG-4). |
| A.8.4 | Access to source code | GOV-3 | MCP tool schemas and server code are version-controlled. Changes require PR review. Access to modify tool definitions is restricted; changes trigger alerts and re-review. |
| A.8.5 | Secure authentication | IAM-1, IAM-2, IAM-3, IAM-6 | Authentication requires approved strong mechanisms. Credentials are stored hashed or in a secrets manager, transmitted only over TLS, never in source code or URLs. Each MCP server uses unique credentials. |
| A.8.6 | Capacity management | AUD-7, RES-1 | Rate limiting controls per-client call rates. Tool execution timeouts prevent runaway agentic loops from exhausting server capacity. Call budgets can be defined per session or user. |
| A.8.7 | Protection against malware | CFG-5, GOV-4 | MCP server dependencies are pinned and scanned for known vulnerabilities in CI (`pip audit`, `npm audit`). Third-party MCP server packages are verified against expected hashes at install time. |
| A.8.8 | Management of technical vulnerabilities | CFG-5, GOV-4 | Dependencies are kept current and scanned for CVEs. Third-party MCP servers are reassessed when significant vulnerabilities are disclosed in their dependencies. |
| A.8.9 | Configuration management | CFG-1, CFG-2, CFG-3, CFG-4 | MCP servers run as dedicated low-privilege users with restricted filesystem access. Backend credentials are scoped to minimum permissions. Tool surface is minimized. Configuration is version-controlled and deviations are detected. |
| A.8.12 | Data leakage prevention | OUT-1, OUT-2, AUD-3 | Tool responses are sanitized to return only required fields. Credentials, tokens, and PII beyond what was requested are stripped from responses. Sensitive data is excluded from logs. |
| A.8.15 | Logging | AUD-1, AUD-2, AUD-3, AUD-4, AUD-5 | Every tool call is logged with: timestamp, session ID, call ID, tool name, caller identity, sanitized input summary, outcome, and duration. Authentication failures and authorization denials generate security events. Logs are forwarded to SIEM and retained per policy. Credentials and tokens are excluded from logs. |
| A.8.16 | Monitoring activities | AUD-6, AUD-7, AUD-4 | Anomaly detection alerts are configured for unusual tool call patterns (high volumes, unusual sequences, after-hours activity, repeated auth failures). Logs are centralized to enable correlation across MCP servers and other systems. |
| A.8.24 | Use of cryptography | TLS-1, TLS-2, TLS-3, IAM-3 | Remote MCP transport uses TLS 1.2+. Weak cipher suites are disabled. API keys are stored using SHA-256 or bcrypt — never plaintext. Cryptographic operations use standard libraries; no custom implementations. |
| A.8.25 | Secure development lifecycle | GOV-3, IV-1, IV-2, IV-3, IV-4 | Tool schema changes go through version-controlled review. Input validation controls (schema validation, path validation, SSRF prevention, injection prevention) are implemented by default in the secure development patterns. Security testing is included in CI. |
| A.8.26 | Application security requirements | IV-1 through IV-5, OUT-1 through OUT-3 | MCP server security requirements include: strict schema validation on all inputs, path traversal protection, SSRF prevention, injection prevention, input size limits, response sanitization, data minimization, and error hardening. See [Input Validation Guide](../build/input-validation.md). |
| A.8.28 | Secure coding | IV-4, OUT-3, CFG-1 | Parameterized queries are required for all database access. Shell execution with user-controlled input is prohibited. Error responses to callers use generic messages; detailed errors are logged server-side only. MCP servers run with minimal OS permissions. |

---

## Coverage by Annex A Domain

| Annex A Domain | Controls Covered |
|----------------|-----------------|
| A.5 Organizational | A.5.1, A.5.10, A.5.14, A.5.15, A.5.23 |
| A.6 People | A.6.3, A.6.6 |
| A.7 Physical | Not mapped (infrastructure-level; outside MCP scope) |
| A.8 Technological | A.8.2, A.8.3, A.8.4, A.8.5, A.8.6, A.8.7, A.8.8, A.8.9, A.8.12, A.8.15, A.8.16, A.8.24, A.8.25, A.8.26, A.8.28 |

---

## MCP-Specific Gaps

ISO 27001:2022 Annex A was designed for general information security management. Several threat categories specific to MCP and AI systems are not well-addressed:

**Prompt Injection** — No Annex A control addresses the risk that data returned by a system component (MCP tool output) can be interpreted as instructions by an AI model. A.8.26 (application security requirements) is the closest analog but does not contemplate AI inference manipulation. Organizations should document this risk explicitly in their risk treatment plan. Compensating controls include output sanitization (OUT-1), tool call policies, and user confirmation gates for sensitive operations.

**Tool Poisoning** — The risk that tool descriptions contain embedded instructions designed to manipulate AI behavior is not covered by any Annex A control. A.5.23 (cloud services) and A.8.7 (malware) are adjacent but insufficient. GOV-4 (third-party vetting) and GOV-3 (change control) provide the primary controls; auditors should request evidence of tool description review and integrity checking.

**Confused Deputy / AI-Mediated Privilege Escalation** — Annex A access controls (A.5.15, A.8.2, A.8.3) address who can access systems, but not the scenario where an authorized AI model is manipulated into taking actions a user didn't authorize. This is a design-level threat requiring compensating controls: tool segmentation so read and write capabilities are not co-located, and human-in-the-loop confirmation gates for write/send/delete operations.

**AI Model as Threat Actor** — ISO 27001 risk assessments typically model external attackers and insiders as threat actors. AI models themselves — when manipulated — can act as an insider threat with whatever permissions the MCP server was granted. Risk assessments should include AI model compromise as an explicit threat scenario.

**Lack of Established Evidence Types** — ISO 27001 audits rely on evidence types (policies, records, configurations, interview responses) that are well-understood for traditional systems. For MCP, auditors and security teams should establish what constitutes evidence for controls like "tool description integrity is maintained" or "prompt injection risk is monitored." Tool definition hashes, tool-call audit logs, and anomaly detection alert records are the primary evidence artifacts.

---

## Related

- [Controls Framework](controls-framework.md)
- [NIST Mapping](nist-mapping.md)
- [SOC 2 Mapping](soc2-mapping.md)
- [Audit Methodology](../audit/audit-methodology.md)
- [MCP in the Enterprise](../../discussions/topics/mcp-in-enterprise.md)
