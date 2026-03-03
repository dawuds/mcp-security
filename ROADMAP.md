# Roadmap

This roadmap reflects planned and in-progress work. Contributions welcome — see [CONTRIBUTING.md](CONTRIBUTING.md).

## Current (v0.1)

- MCP primer, security model, and STRIDE threat model
- Secure development guides (auth, authz, input validation, logging)
- Assessment and audit methodologies with checklists
- Testing methodology and prompt injection test suite
- Controls framework with NIST CSF / SP 800-53 mappings
- Sample MCP servers (minimal, filesystem, API gateway, database, OAuth, multi-tenant)
- Security scripts (MCP scanner, schema validator)
- Attack playbooks (prompt injection, tool poisoning, confused deputy)
- SOC 2 and ISO 27001 compliance mappings

## Near-term

- [ ] MCP client security guide (securing the AI-side of the connection)
- [ ] Supply chain security guide (validating third-party MCP servers)
- [ ] gRPC/SSE transport security guide
- [ ] Additional sample: secrets manager MCP with envelope encryption
- [ ] Automated schema validation in CI for all samples

## Medium-term

- [ ] Threat intelligence feed integration sample
- [ ] Federated identity / OIDC sample
- [ ] MCP audit log aggregation guide (SIEM integration)
- [ ] CIS Controls mapping

## Long-term

- [ ] Interactive security assessment tool
- [ ] MCP security benchmark (automated scoring)
- [ ] Community vulnerability database for known MCP security issues
