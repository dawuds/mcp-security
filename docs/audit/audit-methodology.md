# MCP Audit Methodology

An audit evaluates whether MCP deployments meet defined standards, policies, and controls. Unlike an assessment (which focuses on finding vulnerabilities), an audit measures conformance to requirements.

---

## Audit vs. Assessment

| Dimension | Security Assessment | Audit |
|-----------|--------------------|----- |
| Focus | Finding vulnerabilities | Measuring conformance |
| Approach | Adversarial/exploratory | Evidence-based review |
| Output | Vulnerability findings | Control findings / gaps |
| Standard | Best practices | Defined policy or framework |
| Audience | Security team | Management, compliance, board |

Both are complementary. A complete program includes both.

---

## Audit Scope

Define the scope before starting:

- **Systems in scope:** Which MCP servers, which hosts, which integrations
- **Standards:** What are you auditing against? (Internal policy, NIST CSF, SOC 2, etc.)
- **Time period:** Historical evidence should cover (typically 3-12 months)
- **Evidence types:** Documentation, configuration files, log samples, interviews

---

## Audit Phases

### Phase 1: Planning

1. Define audit scope and objectives
2. Identify applicable policies and standards
3. Request documentation and evidence from the auditee
4. Schedule interviews with MCP server owners and developers

**Evidence to request:**
- MCP server architecture documentation
- Tool definitions and schemas (version-controlled)
- Authentication configuration
- Access control policies and implementation
- Log configuration and samples
- Incident history related to MCP servers
- Dependency management process (how updates are applied)
- Third-party MCP server vetting process (if applicable)

---

### Phase 2: Evidence Collection

**Configuration Review:**
- Review MCP server configuration against secure baseline
- Check OS user accounts and permissions for the server process
- Review credential storage and rotation processes
- Verify TLS configuration for remote servers

**Documentation Review:**
- Is there documented policy for MCP server deployment?
- Is there a process for reviewing and approving new tools?
- Is there a process for vetting third-party MCP servers?
- Are tool schemas version-controlled?

**Log Review:**
- Are audit logs enabled and complete?
- Do logs include required fields (tool name, caller, inputs, outcome)?
- Are sensitive values excluded from logs?
- Is log retention meeting policy requirements?
- Are logs forwarded to a centralized system?

**Access Review:**
- Who has access to deploy or modify MCP servers?
- Are credentials appropriately scoped and rotated?
- Is access to MCP server administration restricted to authorized personnel?

---

### Phase 3: Testing (Audit-Style)

Unlike an assessment, audit testing focuses on verifying that controls exist and function as claimed, not on finding all possible vulnerabilities.

**Sample testing approach:**
- Select a sample of tool calls from logs; verify each was properly logged
- Attempt to call a restricted tool without credentials to verify authentication is enforced
- Review a sample of tool schemas to verify they match documentation
- Verify that the MCP server process is running as the documented low-privilege user

---

### Phase 4: Finding Classification

Classify each finding by:

**Severity:**
| Severity | Definition |
|----------|-----------|
| Critical | Control is absent; direct exploitation risk or compliance violation |
| High | Control is significantly deficient |
| Medium | Control is partially implemented or has notable gaps |
| Low | Minor improvement opportunity; low risk |
| Informational | Observation with no direct risk |

**Control Status:**
| Status | Definition |
|--------|-----------|
| Not Implemented | Control does not exist |
| Partially Implemented | Control exists but is incomplete or inconsistently applied |
| Implemented with Exceptions | Control is in place but exceptions exist without compensating controls |
| Implemented | Control is fully implemented and effective |

---

### Phase 5: Reporting

**Audit Report Structure:**
1. Executive Summary
2. Scope and methodology
3. Overall assessment / opinion
4. Findings (by severity)
5. Control status summary table
6. Recommendations
7. Management response (if applicable)
8. Appendices (evidence, tools list, etc.)

---

## Controls to Audit

See [audit-checklist.md](audit-checklist.md) for the complete control-by-control checklist.

Core control areas:
1. MCP server inventory and change management
2. Access control (authentication and authorization)
3. Secure development (input validation, output handling)
4. Transport security
5. Least privilege and configuration
6. Audit logging and monitoring
7. Third-party MCP server governance
8. Incident response capability

---

## Compliance Mappings

| Control Area | NIST CSF | NIST SP 800-53 | SOC 2 |
|-------------|----------|----------------|-------|
| Authentication | PR.AA | IA-2, IA-5 | CC6.1 |
| Authorization | PR.AA | AC-2, AC-6 | CC6.3 |
| Audit Logging | DE.AE | AU-2, AU-12 | CC7.2 |
| Transport Security | PR.DS | SC-8, SC-28 | CC6.1 |
| Least Privilege | PR.AA | AC-6, CM-7 | CC6.3 |
| Change Management | PR.PS | CM-3, CM-6 | CC8.1 |

For the full mapping, see [Standards: NIST Mapping](../standards/nist-mapping.md).

---

## Related

- [Audit Checklist](audit-checklist.md)
- [Assessment Methodology](../assess/assessment-methodology.md)
- [Controls Framework](../standards/controls-framework.md)
- [NIST Mapping](../standards/nist-mapping.md)
