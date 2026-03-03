# Sample 06: Multi-Tenant MCP

An MCP server that serves multiple tenants from a single process while guaranteeing strict data isolation between them. Each tenant's data is namespaced at the storage layer so cross-tenant access is structurally impossible.

## What It Does

Exposes these tools:
- `set_value` — Store a key-value pair for this tenant (enforces quota)
- `get_value` — Retrieve a stored value by key for this tenant
- `list_keys` — List all keys belonging to this tenant only
- `delete_value` — Delete a stored key-value pair for this tenant
- `get_quota` — Return this tenant's quota usage (used / limit)

## Security Controls Demonstrated

| Control | Implementation |
|---------|---------------|
| Tenant namespacing | All stored keys are prefixed with `tenant:{tenant_id}:` — keys from different tenants can never collide |
| Tenant ID validation | Tenant ID must match `^[a-zA-Z0-9_-]{1,64}$`; invalid IDs are rejected before any operation |
| Cross-tenant prevention | Every read/write/delete operates only on keys within the current tenant's prefix; access-denied responses reveal nothing about other tenants |
| Tenant-scoped audit logging | Every log entry includes `tenant_id` so the audit trail is queryable per-tenant |
| Resource quotas | Each tenant is limited to `MCP_TENANT_QUOTA` (default 50) key-value pairs; `set_value` enforces this atomically |
| No tenant enumeration | Error messages say "key not found" — they never reveal whether a key exists under a different tenant's prefix |

## Configuration

```bash
# Required: the tenant identity for this server session.
# In production this would be derived from the authenticated session
# (e.g. a verified JWT sub claim or an SSO identity).
export MCP_TENANT_ID=acme-corp

# Optional: maximum stored key-value pairs per tenant (default: 50)
export MCP_TENANT_QUOTA=50
```

## Requirements

```
mcp
```

## Running

```bash
pip install -r requirements.txt
MCP_TENANT_ID=acme-corp python server.py
```

## Architecture Note

The in-memory store is a demo artifact. In production, replace `_store` with a database client and enforce row-level security at the database layer (e.g. PostgreSQL RLS policies) so that even a bug in application code cannot allow cross-tenant reads. The tenant ID should be derived from a cryptographically verified identity token, not an environment variable.
