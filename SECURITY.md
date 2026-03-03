# Security Policy

## Scope

This repository contains **educational content and sample code** for understanding MCP security. The sample MCP servers are reference implementations intended to demonstrate security controls — they are not production-ready services.

## Reporting a Vulnerability

### In this repository's own code

If you discover a security vulnerability in the sample code, scripts, or tooling in this repository (e.g., a sample that claims to be secure but actually has an exploitable flaw), please report it via **GitHub's private advisory feature**:

[Report a vulnerability](https://github.com/dawuds/mcp-security/security/advisories/new)

Please include:
- Which file(s) are affected
- A description of the vulnerability
- Steps to reproduce
- Your suggested fix (optional)

We aim to acknowledge reports within 72 hours and resolve confirmed issues within 14 days.

### In MCP itself

Vulnerabilities in the MCP protocol or Anthropic's MCP implementations should be reported to Anthropic via their [responsible disclosure program](https://www.anthropic.com/security).

### In third-party MCP servers

Report vulnerabilities in third-party MCP servers to those projects directly.

## Supported Versions

This repository does not release versioned software. Content is maintained on the `main` branch.

## Security Considerations for Users

The sample MCP servers in this repository are **illustrative**. Before deploying any MCP server in production:

1. Review the security controls against your threat model
2. Perform your own security assessment using the [assessment methodology](docs/assess/assessment-methodology.md)
3. Ensure authentication, authorization, and audit logging are configured for your environment
4. Do not expose MCP servers to untrusted networks without additional controls
