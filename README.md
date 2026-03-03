# MCP Security

A practitioner-focused resource for understanding, building, assessing, auditing, and testing **Model Context Protocol (MCP)** servers securely.

> MCP is Anthropic's open protocol that enables AI models to interact with external tools, data sources, and services. As MCP adoption grows, so does the need for clear security guidance across the full lifecycle.

---

## Who This Is For

| Audience | What you'll find |
|----------|-----------------|
| **MCP Developers** | Secure design patterns, auth guides, input validation, logging |
| **Security Practitioners** | Assessment methodology, attack surface, known vulnerability classes |
| **Auditors / GRC** | Controls frameworks, NIST mappings, audit checklists |
| **AI/ML Engineers** | Threat models, integration security, deployment hardening |

---

## Repository Structure

```
mcp-security/
├── docs/
│   ├── 01-what-is-mcp.md          # MCP primer and architecture
│   ├── 02-security-model.md       # Trust boundaries and attack surface
│   ├── 03-threat-model.md         # STRIDE-based threat model
│   ├── build/                     # Secure MCP development guides
│   ├── assess/                    # Assessment methodology and checklists
│   ├── audit/                     # Audit methodology and checklists
│   ├── test/                      # Testing guides and test cases
│   └── standards/                 # Controls frameworks and compliance mappings
├── samples/
│   ├── 01-minimal-mcp/            # Minimal secure MCP (reference implementation)
│   ├── 02-filesystem-mcp/         # Filesystem MCP with path traversal protection
│   └── 03-api-gateway-mcp/        # API gateway MCP with authentication
└── discussions/
    └── topics/                    # Deep-dives on specific security topics
```

---

## Quick Start

### Understanding MCP Security
1. [What is MCP?](docs/01-what-is-mcp.md) — Architecture and protocol overview
2. [Security Model](docs/02-security-model.md) — Trust boundaries, attack surface
3. [Threat Model](docs/03-threat-model.md) — STRIDE analysis for MCP deployments

### Building Securely
- [Secure Design Principles](docs/build/secure-design.md)
- [Authentication Patterns](docs/build/authentication.md)
- [Authorization & Least Privilege](docs/build/authorization.md)
- [Input Validation](docs/build/input-validation.md)
- [Logging & Monitoring](docs/build/logging-monitoring.md)

### Assessing, Auditing & Testing
- [Assessment Methodology](docs/assess/assessment-methodology.md)
- [Audit Methodology](docs/audit/audit-methodology.md)
- [Testing Methodology](docs/test/testing-methodology.md)
- [Prompt Injection Test Cases](docs/test/prompt-injection-tests.md)

### Standards & Controls
- [MCP Controls Framework](docs/standards/controls-framework.md)
- [NIST CSF / SP 800-53 Mapping](docs/standards/nist-mapping.md)

---

## Key Security Concepts

**Prompt Injection via Tools** — Malicious content returned by MCP tools can redirect or manipulate the AI model's behavior.

**Tool Poisoning** — A compromised or malicious MCP server can expose tools designed to exfiltrate data or escalate privileges.

**Excessive Permission** — MCP servers with broader access than needed increase blast radius if compromised.

**Lack of Audit Trail** — MCP tool calls often bypass traditional logging pipelines, creating blind spots.

**Confused Deputy** — An MCP server acting on behalf of a user may be tricked into taking actions the user didn't authorize.

---

## Sample MCPs

| Sample | Description | Key Controls Demonstrated |
|--------|-------------|--------------------------|
| [01-minimal-mcp](samples/01-minimal-mcp/) | Minimal reference implementation | Schema validation, error handling |
| [02-filesystem-mcp](samples/02-filesystem-mcp/) | Filesystem access | Path traversal protection, allow-lists |
| [03-api-gateway-mcp](samples/03-api-gateway-mcp/) | External API integration | Auth, rate limiting, response sanitization |

---

## Discussions

See [discussions/](discussions/) for in-depth explorations of:
- [Prompt Injection in MCP Context](discussions/topics/prompt-injection.md)
- [Tool Poisoning](discussions/topics/tool-poisoning.md)
- [MCP in the Enterprise](discussions/topics/mcp-in-enterprise.md)

---

## Contributing

Contributions are welcome — whether that's new sample MCPs, improved checklists, additional threat scenarios, or corrections. See [CONTRIBUTING.md](CONTRIBUTING.md) to get started.

---

## License

[MIT](LICENSE) — use freely, attribution appreciated.
