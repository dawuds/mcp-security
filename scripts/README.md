# MCP Security Scripts

Two standalone CLI tools for auditing MCP deployments. Both require only the Python standard library (Python 3.11+) and produce coloured terminal output by default, with `--json` for machine-readable output.

---

## mcp-scanner.py

Audits an MCP server configuration file (e.g. Claude Desktop's `claude_desktop_config.json`) for security misconfigurations.

### Usage

```bash
# Audit a config file
python scripts/mcp-scanner.py claude_desktop_config.json

# Machine-readable JSON output (useful for CI or piping to jq)
python scripts/mcp-scanner.py --json claude_desktop_config.json

# Read from stdin
cat claude_desktop_config.json | python scripts/mcp-scanner.py -

# Disable colour output
python scripts/mcp-scanner.py --no-colour claude_desktop_config.json
```

### Expected input format

The config file must be a JSON object matching the Claude Desktop / MCP config schema:

```json
{
  "mcpServers": {
    "my-server": {
      "command": "npx",
      "args": ["-y", "@modelcontextprotocol/server-filesystem", "/tmp/workspace"],
      "env": {
        "MCP_LOG_LEVEL": "info"
      }
    }
  }
}
```

### Checks performed

| ID | Severity | Description |
|----|----------|-------------|
| `TRANSPORT_NO_TLS` | HIGH | Server config references an `http://` URL (no TLS) |
| `SENSITIVE_ENV_VAR` | HIGH | Env block contains keys matching secret patterns (`*TOKEN*`, `*PASSWORD*`, `*KEY*`, etc.) |
| `SHELL_COMMAND` | HIGH | Command is a shell interpreter (`bash`, `sh`, `powershell`, etc.) |
| `NO_ENV_ISOLATION` | LOW | No `env` block — process inherits the full parent environment |
| `SUSPICIOUS_ARG` | MEDIUM | An arg contains shell metacharacters (`\|`, `;`, `&&`, `\|\|`, `$(`, backtick) |
| `TOO_MANY_SERVERS` | MEDIUM | More than 20 MCP servers configured (large attack surface) |
| `DUPLICATE_SERVER_NAME` | MEDIUM | Two entries share the same server name (shadow risk) |
| `EMPTY_SERVER_NAME` | MEDIUM | Server has an empty or blank name |
| `EMPTY_SERVER_COMMAND` | MEDIUM | Server entry has no `command` field |

### Exit codes

| Code | Meaning |
|------|---------|
| `0` | No HIGH findings |
| `1` | One or more HIGH findings |
| `2` | Usage error (bad file path, invalid JSON, etc.) |

---

## validate-schema.py

Validates MCP tool `inputSchema` definitions (JSON Schema) against security best practices. Poorly constrained schemas expose tools to malformed inputs, DoS, and ambiguous AI model behaviour.

### Usage

```bash
# Validate a single tool schema file
python scripts/validate-schema.py tool-schema.json

# Machine-readable JSON output
python scripts/validate-schema.py --json tool-schema.json

# Disable colour output
python scripts/validate-schema.py --no-colour tool-schema.json
```

### Expected input format

Either a single tool object:

```json
{
  "name": "search_documents",
  "inputSchema": {
    "type": "object",
    "properties": {
      "query": {
        "type": "string",
        "description": "The search query",
        "minLength": 1,
        "maxLength": 500
      }
    },
    "required": ["query"],
    "additionalProperties": false
  }
}
```

Or an array of tool objects:

```json
[
  {"name": "tool_a", "inputSchema": { ... }},
  {"name": "tool_b", "inputSchema": { ... }}
]
```

### Checks performed

| ID | Severity | Description |
|----|----------|-------------|
| `NO_ADDITIONAL_PROPERTIES_FALSE` | HIGH | Schema is missing `additionalProperties: false` — accepts unexpected fields |
| `OBJECT_MISSING_PROPERTIES` | HIGH | An `object`-typed schema has no `properties` definition (maximally permissive) |
| `MISSING_TYPE` | HIGH | A field has no `type` specified — any JSON value is accepted |
| `TYPE_ANY` | HIGH | A field uses the non-standard `type: "any"` |
| `MISSING_INPUT_SCHEMA` | HIGH | Tool entry has no `inputSchema` |
| `STRING_MISSING_MAX_LENGTH` | MEDIUM | A string field has no `maxLength` — enables DoS via large inputs |
| `NO_REQUIRED_ARRAY` | MEDIUM | Schema has no `required` array — every field is optional |
| `NUMERIC_NO_BOUNDS` | LOW | A numeric field has no `minimum`/`maximum` bounds |
| `MISSING_DESCRIPTION` | LOW | A property has no `description` — increases misuse risk |
| `REQUIRED_STRING_ALLOWS_EMPTY` | LOW | A required string field has `minLength: 0` — allows empty strings |

Nested `object` schemas within `properties` are also checked recursively.

### Exit codes

| Code | Meaning |
|------|---------|
| `0` | No HIGH findings |
| `1` | One or more HIGH findings |
| `2` | Usage error (bad file path, invalid JSON, etc.) |

---

## Making the scripts executable

```bash
chmod +x scripts/mcp-scanner.py scripts/validate-schema.py

# Then run directly (shebang is already set to /usr/bin/env python3)
./scripts/mcp-scanner.py claude_desktop_config.json
./scripts/validate-schema.py tool-schema.json
```

## Using in CI

Both tools exit with code `1` when HIGH severity findings are present, making them suitable as CI gate checks:

```yaml
# Example GitHub Actions step
- name: Audit MCP config
  run: python scripts/mcp-scanner.py --json claude_desktop_config.json

- name: Validate tool schemas
  run: python scripts/validate-schema.py --json schemas/tools.json
```

The `--json` flag produces output that can be piped to `jq` for further filtering or reporting:

```bash
python scripts/mcp-scanner.py --json config.json | jq '.findings[] | select(.severity == "HIGH")'
```
