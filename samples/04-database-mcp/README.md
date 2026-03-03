# Sample 04: Database MCP

An MCP server that exposes secure, read-only access to a SQLite database. Demonstrates how to give an AI model structured database access without exposing raw SQL execution.

## What It Does

Exposes these tools:
- `list_queries` — list all available named queries and their parameter descriptions
- `run_query` — execute a named query with validated parameters
- `list_tables` — list non-system tables in the database
- `describe_table` — show columns and types for a named table

There is deliberately **no** `run_sql` tool. The AI model can only invoke pre-approved queries.

## Security Controls Demonstrated

| Control | Implementation |
|---------|---------------|
| Query allowlisting | Only named queries defined in `NAMED_QUERIES` can execute; raw SQL is never accepted |
| Parameterized queries | Value parameters use sqlite3 `?` binding — no string interpolation |
| Identifier allowlisting | Table and column names are validated against the live DB schema before substitution |
| Read-only mode | `PRAGMA query_only=ON` blocks any write statement at the engine level |
| Result size limits | Rows are capped at `MCP_MAX_ROWS` (default 100, hard max 1000) |
| Schema introspection sanitized | `list_tables` and `describe_table` exclude SQLite system tables |
| Audit logging | Every tool call logged with query name and parameter summary |
| Safe error responses | Database errors do not reveal SQL or schema details to the caller |

## Named Queries

| Name | Description | Parameters |
|------|-------------|------------|
| `count_rows` | Count rows in a table | `table` |
| `recent_rows` | Most recent rows by rowid | `table`, `limit` (1–100) |
| `search_text` | LIKE search in a column | `table`, `column`, `search_term` (max 100 chars), `limit` (1–100) |
| `distinct_values` | Distinct values in a column | `table`, `column`, `limit` (1–100) |

## Configuration

```bash
# Path to the SQLite database file (default: /tmp/mcp-demo.db)
export MCP_DB_PATH=/path/to/your/database.db

# Enforce read-only mode — set to "false" only if writes are intentional (default: true)
export MCP_READ_ONLY=true

# Maximum rows returned per query (default: 100, hard maximum: 1000)
export MCP_MAX_ROWS=100
```

## Requirements

```
mcp>=1.0.0
```

## Running

```bash
pip install -r requirements.txt
python server.py
```

On first run the server creates a demo SQLite database at `MCP_DB_PATH` (default `/tmp/mcp-demo.db`) with `products` and `orders` tables populated with sample data.

## Example MCP Client Configuration

```json
{
  "mcpServers": {
    "database": {
      "command": "python",
      "args": ["/path/to/samples/04-database-mcp/server.py"],
      "env": {
        "MCP_DB_PATH": "/path/to/your/database.db",
        "MCP_READ_ONLY": "true",
        "MCP_MAX_ROWS": "50"
      }
    }
  }
}
```

## Example Tool Calls

```
list_tables
→ ["orders", "products"]

describe_table {"table": "products"}
→ columns: id (INTEGER), name (TEXT), category (TEXT), price (REAL)

list_queries
→ count_rows, recent_rows, search_text, distinct_values

run_query {"query_name": "count_rows", "params": {"table": "products"}}
→ {"row_count": 1, "rows": [{"count": 5}]}

run_query {"query_name": "search_text", "params": {"table": "products", "column": "category", "search_term": "Elec%", "limit": 10}}
→ rows matching Electronics
```

## Security Notes

- **Adding new queries**: extend `NAMED_QUERIES` in `server.py`. Never add a query whose SQL template includes unvalidated user input.
- **Identifier substitution**: table and column names from callers go through `validate_identifier()`, which checks them against the live schema. They are only substituted into the SQL template after this check passes.
- **Production databases**: run the server process under an OS user with read-only filesystem permissions on the database file, in addition to `PRAGMA query_only`.
- **Sensitive columns**: if your database contains columns that should never be returned (e.g., password hashes, tokens), filter them in the query definitions or use a database view with only safe columns exposed.
