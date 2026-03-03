# MCP in the Enterprise

## The Enterprise MCP Challenge

Enterprise AI deployments are increasingly adding MCP integrations to give AI models access to internal systems — file shares, databases, CRM systems, email, HR platforms, and more. This creates significant security and governance challenges that don't have established playbooks yet.

This discussion covers the key considerations for security and GRC teams navigating MCP in enterprise environments.

---

## What Makes Enterprise MCP Different

**Scale:** Enterprises may deploy dozens of MCP servers — internal and third-party — across multiple teams and systems. The inventory and governance problem is non-trivial.

**Sensitive data:** Enterprise MCP servers typically access genuinely sensitive data: employee records, financial data, customer information, proprietary IP.

**Regulatory context:** Many enterprises operate under compliance frameworks (SOC 2, HIPAA, PCI-DSS, GDPR) that impose specific requirements on data access, logging, and third-party governance.

**Multiple stakeholders:** Security teams, IT, compliance, legal, business units, and AI product teams all have a stake — and often different priorities.

**Existing controls don't map directly:** Traditional DLP, CASB, and access control frameworks weren't designed with AI-mediated data access in mind.

---

## Governance Framework

Enterprises need answers to these questions before deploying MCP:

### 1. Who approves new MCP server connections?

Establish a clear approval process:
- Business justification: what problem does this MCP server solve?
- Technical review: what tools are exposed, what data is accessed, what permissions are needed?
- Security review: what are the risks? Are controls adequate?
- Compliance review: does this introduce new regulatory exposure?

Treat MCP server connections with the same rigor as new third-party integrations.

### 2. What data can MCP servers access?

Define a data classification policy for MCP:

| Data Class | MCP Access Policy |
|-----------|------------------|
| Public | Generally permitted |
| Internal | Permitted with approved MCP server + logging |
| Confidential | Requires elevated review, additional controls, user confirmation for reads |
| Restricted (PII, PHI, PCI) | Restricted to specific approved use cases; enhanced logging, DLP integration |

### 3. What actions can AI models take autonomously vs. requiring approval?

Define a policy for autonomous vs. human-approved actions:

| Action Type | Policy |
|------------|--------|
| Read / query (non-sensitive) | Autonomous permitted |
| Read (confidential data) | Autonomous with audit log |
| Write / create | Requires user confirmation |
| Send / notify | Requires user confirmation |
| Delete / irreversible | Requires explicit user approval; consider two-step confirmation |
| Admin actions | Prohibited for AI unless specifically approved use case |

### 4. How are third-party MCP servers vetted?

Create a vetting process including:
- Source code review (or audit report if closed-source)
- Data access review: what does the server access?
- Vendor security assessment (questionnaire or formal assessment)
- Tool definition review
- Contractual requirements (data processing agreements, security SLAs)

---

## Identity and Access Management Considerations

### AI-Specific Service Accounts

Create dedicated service accounts for MCP-mediated AI access:
- Separate from human user accounts and from other service accounts
- Named clearly (e.g., `svc-ai-mcp-crm-readonly`)
- Scoped to minimum permissions for the specific MCP use case
- Audited separately from human access reviews

### User-Delegated Access

In some architectures, the AI acts on behalf of a specific user (delegated access). This raises additional questions:
- Does the user understand what they're authorizing?
- Can the user revoke delegated access?
- Are the AI's actions attributed to the user in audit logs?

### Separation of AI and Human Audit Trails

AI-mediated access should be distinguishable from human access in audit logs. This matters for:
- Incident investigation (was this a human or an AI?)
- Compliance reporting (what data did the AI access vs. humans?)
- Anomaly detection (AI access patterns differ from human patterns)

---

## Monitoring and Detection

Enterprise security teams should add MCP to their monitoring scope:

**SIEM integration:**
- Ingest MCP audit logs alongside other application and infrastructure logs
- Create correlation rules for suspicious MCP tool call patterns
- Include MCP events in alert escalation workflows

**DLP considerations:**
- Traditional DLP inspects network traffic and file transfers
- MCP moves data through the AI model's context — traditional DLP won't see this
- Consider output monitoring: what does the AI model return to users after tool calls?

**Behavioral baselines:**
- Establish normal patterns for each AI+MCP deployment (what tools are called, at what volumes, at what times)
- Alert on deviations from baseline

**Key metrics to track:**
- Tool call volume per session/user
- Distribution of tools called (alert on new tools appearing in production)
- Error rates per tool (spikes may indicate probing or misconfiguration)
- External data access (volumes of data retrieved via MCP tools)

---

## Compliance Considerations

### GDPR / Privacy Regulations

- AI-mediated access to personal data must be logged and traceable to a lawful basis
- Subject access requests: can you produce what personal data the AI accessed about a subject?
- Data minimization: AI tool responses should not return more personal data than needed

### HIPAA

- AI access to PHI through MCP requires a Business Associate Agreement with the MCP server operator (if third-party)
- PHI access must be logged and auditable
- PHI must not persist in AI model logs beyond what's required

### SOC 2

- MCP servers and AI integrations should be included in the system boundary for SOC 2
- Controls must cover logical access, audit logging, and monitoring for the MCP layer

### PCI-DSS

- If MCP servers have access to cardholder data, they're in scope for PCI-DSS
- Access controls, logging, and network segmentation requirements apply

---

## Risk Management

**Accept, transfer, or mitigate:**

For each MCP integration, make an explicit risk decision:
- What's the worst case if this MCP server is compromised or behaves maliciously?
- What's the data exposure if prompt injection succeeds?
- What controls reduce these risks to an acceptable level?
- Is residual risk accepted? By whom?

**Red team your MCP deployments:**

Include MCP servers in red team exercises. Specific scenarios to test:
- Can a tester inject instructions via content the AI will retrieve?
- Can a tester escalate privileges through MCP tools?
- What happens if a third-party MCP server is replaced with a malicious one?

---

## Incident Response for MCP

Update IR procedures to address MCP-specific scenarios:

**Detection:** How will you know if an MCP server was compromised or if prompt injection succeeded?
- Alert thresholds on anomalous tool call patterns
- User reports of unexpected AI behavior

**Containment:** How do you isolate a compromised MCP server?
- Revoke its credentials immediately
- Disconnect it from the MCP host
- Block network access if remote

**Investigation:** How do you reconstruct what happened?
- MCP audit logs — were they complete?
- What tools were called, when, by whom (which AI session)?
- What data was accessed or modified?

**Recovery:** How do you restore trust?
- Review and re-vet the MCP server before reconnecting
- Rotate any credentials the MCP server had access to
- Assess what data may have been exfiltrated

---

## The Bottom Line

MCP is powerful and will become pervasive in enterprise AI deployments. The security and governance challenges are real but manageable with the right controls. The key principles:

1. **Treat MCP like any other third-party integration** — with formal approval, vetting, and ongoing monitoring
2. **Apply least privilege aggressively** — the AI should access only what it needs for the specific task
3. **Log everything** — MCP creates new blind spots; explicit logging closes them
4. **Require human approval for high-impact actions** — keep humans in the loop for write, send, and delete operations
5. **Plan for incidents** — update IR procedures before you need them

---

## Related

- [Controls Framework](../../docs/standards/controls-framework.md)
- [NIST Mapping](../../docs/standards/nist-mapping.md)
- [Audit Methodology](../../docs/audit/audit-methodology.md)
- [Logging & Monitoring](../../docs/build/logging-monitoring.md)
