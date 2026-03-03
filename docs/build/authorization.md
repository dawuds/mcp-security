# Authorization & Least Privilege for MCP Servers

Authorization answers: **what is this caller allowed to do?**

Authentication tells you who is calling. Authorization determines what they're permitted to do. Both are required.

---

## Authorization Models

### 1. Tool-Level Authorization

Control which tools a given client/user can call.

**Use cases:**
- Admin tools (restart, config reload) restricted to admin clients
- Write tools (send email, delete file) restricted to elevated sessions
- Read tools open to all authenticated clients

**Implementation (decorator pattern, Python):**
```python
from functools import wraps

def require_scope(scope: str):
    def decorator(func):
        @wraps(func)
        def wrapper(*args, context: RequestContext, **kwargs):
            if scope not in context.token_scopes:
                raise PermissionError(f"Missing required scope: {scope}")
            return func(*args, context=context, **kwargs)
        return wrapper
    return decorator

@require_scope("files:read")
def read_file(path: str, context: RequestContext) -> str:
    ...

@require_scope("files:write")
def write_file(path: str, content: str, context: RequestContext) -> None:
    ...
```

### 2. Resource-Level Authorization

Control which resources a given client/user can access within a tool.

**Use cases:**
- A user can only read files in their own workspace directory
- A user can only query records they own in a database
- An AI agent can only access resources scoped to the current session

**Implementation (path scoping):**
```python
import os

def get_user_root(user_id: str) -> str:
    return os.path.join(BASE_DIR, "workspaces", user_id)

def read_file(path: str, user_id: str) -> str:
    user_root = get_user_root(user_id)
    # Resolve to absolute, then verify it's within user_root
    abs_path = os.path.realpath(os.path.join(user_root, path))
    if not abs_path.startswith(os.path.realpath(user_root) + os.sep):
        raise PermissionError("Access outside user workspace is not permitted")
    with open(abs_path) as f:
        return f.read()
```

### 3. Operation-Level Authorization

Distinguish between read and write operations even on the same resource type.

| Operation Class | Examples | Authorization Level |
|----------------|----------|---------------------|
| Read | read_file, query_db, get_record | Standard authenticated |
| Write | write_file, update_record | Elevated or explicit consent |
| Delete | delete_file, drop_table | High privilege + confirmation |
| Admin | reload_config, add_user | Admin scope only |
| Send/Notify | send_email, post_message | Explicit scope |

---

## Least Privilege in Practice

### OS-Level
```bash
# Create dedicated user for MCP server
useradd -r -s /bin/false mcp-filesystem

# Only grant access to the directories it needs
chown -R mcp-filesystem:mcp-filesystem /var/mcp/workspaces
chmod 750 /var/mcp/workspaces

# Run the server as that user
sudo -u mcp-filesystem python mcp_server.py
```

### API Credentials
- Don't use an admin API key if read-only access suffices
- Create service accounts with minimal API permissions
- Use environment-specific credentials (dev/staging/prod are separate)

### Database
```sql
-- Create a minimal DB user for the MCP server
CREATE USER mcp_reader WITH PASSWORD '...';
GRANT SELECT ON TABLE relevant_table TO mcp_reader;
-- Do NOT grant INSERT, UPDATE, DELETE, DROP, etc.
```

---

## Consent Gates

For high-impact operations, consider requiring explicit user confirmation rather than allowing the AI model to call tools autonomously.

This is a host-level control (implemented in the MCP client/host), but MCP server design should account for it:
- Clearly distinguish destructive/write operations from read operations in your tool definitions
- Use tool names and descriptions that make the impact obvious (e.g., `delete_file_permanently` not `remove`)
- Return a preview/confirmation step before executing irreversible actions

**Example pattern — two-phase tool:**
```python
# Phase 1: Preview (returns what would happen, doesn't act)
@tool
def delete_files_preview(pattern: str) -> dict:
    files = list_matching_files(pattern)
    return {"would_delete": files, "count": len(files), "confirm_token": generate_token(files)}

# Phase 2: Execute (requires the confirm_token from phase 1)
@tool
def delete_files_execute(confirm_token: str) -> dict:
    files = validate_and_consume_token(confirm_token)
    for f in files:
        os.remove(f)
    return {"deleted": files}
```

---

## Multi-Tenant Authorization

If your MCP server serves multiple users/tenants:
- Enforce tenant isolation at the data layer — never rely on the AI model to enforce it
- Validate that every resource access includes tenant context
- Log tenant context with every operation
- Regularly test cross-tenant isolation

---

## Authorization Failure Handling

- Return `403 Forbidden` (not `404`) for authorization failures on known resources
- Log authorization failures with context (user, resource, tool, timestamp)
- Alert on repeated authorization failures — may indicate a probing attempt
- Do not reveal the existence of resources the caller can't access (use 404 for those)

---

## Related

- [Authentication Patterns](authentication.md)
- [Secure Design Principles](secure-design.md)
- [Input Validation](input-validation.md)
