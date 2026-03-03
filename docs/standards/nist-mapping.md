# NIST Framework Mappings for MCP Security Controls

Maps the [MCP Controls Framework](controls-framework.md) to NIST CSF 2.0 and NIST SP 800-53 Rev 5.

---

## NIST CSF 2.0 Mapping

| MCP Control | CSF Function | CSF Category | CSF Subcategory |
|-------------|-------------|-------------|-----------------|
| GOV-1 (Inventory) | IDENTIFY | Asset Management (AM) | ID.AM-01 |
| GOV-2 (Ownership) | GOVERN | Organizational Context (OC) | GV.OC-05 |
| GOV-3 (Change Control) | PROTECT | Platform Security (PS) | PR.PS-04 |
| GOV-4 (Third-Party Vetting) | IDENTIFY | Risk Assessment (RA) | ID.RA-06 |
| IAM-1 (Authentication) | PROTECT | Identity Management (AA) | PR.AA-03 |
| IAM-2 (Auth Mechanisms) | PROTECT | Identity Management (AA) | PR.AA-03 |
| IAM-3 (Credential Security) | PROTECT | Identity Management (AA) | PR.AA-05 |
| IAM-4 (Credential Rotation) | PROTECT | Identity Management (AA) | PR.AA-05 |
| IAM-5 (Least Privilege) | PROTECT | Identity Management (AA) | PR.AA-05 |
| IAM-6 (Unique Credentials) | PROTECT | Identity Management (AA) | PR.AA-05 |
| CFG-1 (OS Least Privilege) | PROTECT | Platform Security (PS) | PR.PS-01 |
| CFG-2 (Filesystem Permissions) | PROTECT | Platform Security (PS) | PR.PS-01 |
| CFG-3 (Credential Scoping) | PROTECT | Identity Management (AA) | PR.AA-05 |
| CFG-4 (Minimal Tool Surface) | PROTECT | Platform Security (PS) | PR.PS-01 |
| CFG-5 (Dependency Mgmt) | IDENTIFY | Risk Assessment (RA) | ID.RA-01 |
| IV-1 (Schema Validation) | PROTECT | Data Security (DS) | PR.DS-02 |
| IV-2 (Path Validation) | PROTECT | Data Security (DS) | PR.DS-02 |
| IV-3 (SSRF Prevention) | PROTECT | Data Security (DS) | PR.DS-02 |
| IV-4 (Injection Prevention) | PROTECT | Data Security (DS) | PR.DS-02 |
| IV-5 (Size Limits) | PROTECT | Platform Security (PS) | PR.PS-01 |
| OUT-1 (Response Sanitization) | PROTECT | Data Security (DS) | PR.DS-02 |
| OUT-2 (Data Minimization) | PROTECT | Data Security (DS) | PR.DS-01 |
| OUT-3 (Error Hardening) | PROTECT | Platform Security (PS) | PR.PS-06 |
| TLS-1 (Enforce TLS) | PROTECT | Data Security (DS) | PR.DS-02 |
| TLS-2 (Certificate Validity) | PROTECT | Data Security (DS) | PR.DS-02 |
| TLS-3 (Cipher Hardening) | PROTECT | Data Security (DS) | PR.DS-02 |
| AUD-1 (Tool Call Logging) | DETECT | Adverse Event Analysis (AE) | DE.AE-03 |
| AUD-2 (Security Event Logging) | DETECT | Adverse Event Analysis (AE) | DE.AE-03 |
| AUD-3 (Sensitive Data Exclusion) | PROTECT | Data Security (DS) | PR.DS-01 |
| AUD-4 (Centralized Logging) | DETECT | Adverse Event Analysis (AE) | DE.AE-03 |
| AUD-5 (Log Retention) | PROTECT | Data Security (DS) | PR.DS-11 |
| AUD-6 (Anomaly Detection) | DETECT | Adverse Event Analysis (AE) | DE.AE-06 |
| AUD-7 (Rate Limiting) | PROTECT | Platform Security (PS) | PR.PS-01 |
| RES-1 (Timeouts) | PROTECT | Platform Security (PS) | PR.PS-01 |
| RES-2 (Graceful Errors) | PROTECT | Platform Security (PS) | PR.PS-06 |
| RES-3 (IR Procedures) | RESPOND | Incident Management (IM) | RS.MA-01 |

---

## NIST SP 800-53 Rev 5 Mapping

| MCP Control | SP 800-53 Control | Control Name |
|-------------|------------------|-------------|
| GOV-1 | CM-8 | System Component Inventory |
| GOV-2 | PM-2 | Information Security Program Leadership Roles |
| GOV-3 | CM-3 | Configuration Change Control |
| GOV-4 | SR-3 | Supply Chain Controls and Processes |
| IAM-1 | IA-2 | Identification and Authentication (Organizational Users) |
| IAM-2 | IA-5 | Authenticator Management |
| IAM-3 | IA-5(1) | Authenticator Management / Password-Based Authentication |
| IAM-4 | IA-5(1) | Authenticator Management / Password-Based Authentication |
| IAM-5 | AC-6 | Least Privilege |
| IAM-6 | IA-5 | Authenticator Management |
| IAM-7 | AC-2 | Account Management |
| CFG-1 | AC-6(1) | Least Privilege / Authorize Access to Security Functions |
| CFG-2 | AC-3 | Access Enforcement |
| CFG-3 | AC-6 | Least Privilege |
| CFG-4 | CM-7 | Least Functionality |
| CFG-5 | RA-5 | Vulnerability Monitoring and Scanning |
| IV-1 | SI-10 | Information Input Validation |
| IV-2 | SI-10 | Information Input Validation |
| IV-3 | SI-10 | Information Input Validation |
| IV-4 | SI-10 | Information Input Validation |
| IV-5 | SC-5 | Denial-of-Service Protection |
| OUT-1 | SI-10 | Information Input Validation |
| OUT-2 | AC-23 | Data Mining Protection |
| OUT-3 | SI-11 | Error Handling |
| TLS-1 | SC-8 | Transmission Confidentiality and Integrity |
| TLS-2 | SC-8 | Transmission Confidentiality and Integrity |
| TLS-3 | SC-8(1) | Cryptographic Protection |
| AUD-1 | AU-2 | Event Logging |
| AUD-2 | AU-12 | Audit Record Generation |
| AUD-3 | AU-3 | Content of Audit Records |
| AUD-4 | AU-9 | Protection of Audit Information |
| AUD-5 | AU-11 | Audit Record Retention |
| AUD-6 | SI-4 | System Monitoring |
| AUD-7 | SC-5 | Denial-of-Service Protection |
| RES-1 | SC-5 | Denial-of-Service Protection |
| RES-2 | SI-11 | Error Handling |
| RES-3 | IR-4 | Incident Handling |

---

## Coverage Summary

| NIST CSF Function | MCP Controls Mapped |
|------------------|---------------------|
| GOVERN | 2 |
| IDENTIFY | 4 |
| PROTECT | 25 |
| DETECT | 4 |
| RESPOND | 1 |
| RECOVER | 0 |

> **Note:** RECOVER controls (backup, restoration) are not specific to MCP and are typically handled at the infrastructure level. See your organization's business continuity policies for recovery controls.

---

## Additional Frameworks

Future additions to this document will include mappings to:
- ISO/IEC 27001:2022
- CIS Controls v8
- SOC 2 Trust Services Criteria
- OWASP Top 10 for LLM Applications

Contributions welcome — see [CONTRIBUTING.md](../../CONTRIBUTING.md).

---

## Related

- [Controls Framework](controls-framework.md)
- [Audit Checklist](../audit/audit-checklist.md)
