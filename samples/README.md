# Sample MCPs

Working MCP server implementations demonstrating security controls. Each sample is runnable and annotated with security rationale.

---

## Samples

| Sample | Description | Key Security Controls |
|--------|-------------|----------------------|
| [01-minimal-mcp](01-minimal-mcp/) | Reference implementation — minimal but complete | Schema validation, error handling, audit logging |
| [02-filesystem-mcp](02-filesystem-mcp/) | Filesystem read/write with security controls | Path validation, allowlists, least privilege |
| [03-api-gateway-mcp](03-api-gateway-mcp/) | External API integration | Auth, SSRF prevention, rate limiting, response sanitization |

---

## Requirements

All samples require Python 3.10+ and the MCP SDK:

```bash
pip install mcp
```

Each sample directory contains its own `requirements.txt` and `README.md`.

---

## Running a Sample

```bash
cd samples/01-minimal-mcp
pip install -r requirements.txt
python server.py
```

To test with Claude Desktop, add the server to your `claude_desktop_config.json`:

```json
{
  "mcpServers": {
    "minimal": {
      "command": "python",
      "args": ["/path/to/samples/01-minimal-mcp/server.py"]
    }
  }
}
```

---

## Security Notes

These samples are for **educational and reference purposes**. Before deploying any MCP server in production:
- Review the security controls for your specific threat model
- Run the [assessment checklist](../docs/assess/assessment-checklist.md)
- Apply the [secure design principles](../docs/build/secure-design.md)
