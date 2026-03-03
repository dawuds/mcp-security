# Contributing to mcp-security

Thank you for contributing. This repo covers a lot of ground — documentation, sample code, checklists, and discussion. Here's how to contribute effectively to each area.

---

## Ways to Contribute

- **New sample MCPs** — Working implementations that demonstrate security controls
- **Improved checklists** — More complete or refined assessment/audit checklists
- **New threat scenarios** — Attack patterns or vulnerability classes not yet covered
- **Standards mappings** — Mappings to additional frameworks (ISO 27001, SOC 2, CIS, etc.)
- **Corrections** — Errors in existing content, outdated information
- **Discussions** — Deep-dives on specific security topics

---

## Ground Rules

1. **Be accurate.** Don't speculate — if you're unsure, say so or open an issue to discuss.
2. **Be practical.** Content should be actionable, not theoretical.
3. **No proprietary content.** Don't include code or content you don't have the right to share.
4. **No live exploit code.** Proof-of-concept test cases are fine; weaponized exploits are not.

---

## Submitting a Sample MCP

Sample MCPs live in `samples/`. Each sample should:

- Have its own directory: `samples/NN-descriptive-name/`
- Include a `README.md` explaining:
  - What the MCP does
  - Security controls demonstrated
  - Known limitations or trade-offs
  - How to run it
- Be written in Python (preferred) or TypeScript
- Use the official MCP SDK (`mcp` Python package or `@modelcontextprotocol/sdk`)
- Demonstrate at least one concrete security control

---

## Submitting Documentation

Documentation lives in `docs/`. Use Markdown. Structure your content with clear headings. Link to references where relevant.

For new guides under `docs/build/`, `docs/assess/`, `docs/audit/`, or `docs/test/`, follow the existing file structure and naming conventions.

---

## Pull Request Process

1. Fork the repository
2. Create a branch: `git checkout -b feature/your-topic`
3. Make your changes
4. Submit a pull request with a clear description of what you've added or changed and why

---

## Opening Issues

Use GitHub Issues for:
- Reporting errors or outdated content
- Proposing new topics or samples
- Requesting clarification on existing content

---

## Code of Conduct

Be professional. This is a technical resource used by practitioners. Keep discussion focused on security, accuracy, and practicality.
