# Sample 02: Filesystem MCP

An MCP server providing read and write access to a defined workspace directory, with robust security controls to prevent path traversal and unauthorized access.

## What It Does

Exposes these tools:
- `read_file` — Read a file within the allowed workspace
- `write_file` — Write content to a file within the allowed workspace
- `list_directory` — List files in a directory within the allowed workspace
- `file_exists` — Check if a file exists

## Security Controls Demonstrated

| Control | Implementation |
|---------|---------------|
| Path traversal prevention | `os.path.realpath` + allowlist check before any file operation |
| Allowlist-based access | All paths must resolve within `WORKSPACE_DIR` |
| File size limits | Maximum read size enforced before opening |
| Input schema validation | Strict schemas with `additionalProperties: false` |
| Minimal permissions | Server should run as a user with access only to the workspace |
| Audit logging | Every file operation logged with path and outcome |
| Safe error responses | Permissions errors don't reveal whether files exist outside workspace |

## Known Limitations

- No authentication — this is a local (stdio) server; authentication is inherited from the OS
- Write operations are unrestricted within the workspace — add user-level authorization if needed
- Does not support symlinks that point outside the workspace (intentionally)

## Configuration

Set `WORKSPACE_DIR` in the environment or modify the default in `server.py`:

```bash
export MCP_WORKSPACE_DIR=/home/user/workspace
python server.py
```

## Requirements

```
mcp>=1.0.0
```

## Running

```bash
pip install -r requirements.txt
MCP_WORKSPACE_DIR=/tmp/test-workspace python server.py
```
