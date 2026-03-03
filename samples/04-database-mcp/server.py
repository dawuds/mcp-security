"""
Sample 04: Database MCP Server

Demonstrates secure SQL database access via MCP using SQLite.

Key security controls:
- Query allowlisting: only pre-defined named queries can be executed;
  no raw SQL is ever accepted from the AI model or caller.
- Parameterized queries: all user-supplied values are passed via sqlite3
  parameter binding — string interpolation into SQL is never used.
- Read-only mode: PRAGMA query_only=ON blocks any write statement when
  MCP_READ_ONLY=true (the default).
- Result size limits: rows returned are capped at MCP_MAX_ROWS (default 100).
- Schema introspection allowed but sanitized: list_tables and describe_table
  filter out SQLite system tables (sqlite_*).
- No raw query tool: the MCP schema does NOT expose a run_sql tool; callers
  can only invoke named, pre-approved queries.

Environment variables:
  MCP_DB_PATH     — path to the SQLite database file (default: /tmp/mcp-demo.db)
  MCP_READ_ONLY   — set to "true" to enforce read-only mode (default: true)
  MCP_MAX_ROWS    — maximum rows returned per query (default: 100)
"""

import json
import logging
import os
import sqlite3
import sys
import time
import uuid
from typing import Any

from mcp.server import Server
from mcp.server.stdio import stdio_server
from mcp.types import (
    CallToolRequest,
    CallToolResult,
    ListToolsRequest,
    ListToolsResult,
    TextContent,
    Tool,
)

# ---------------------------------------------------------------------------
# Configuration
# ---------------------------------------------------------------------------

DB_PATH = os.environ.get("MCP_DB_PATH", "/tmp/mcp-demo.db")

# Read-only mode: when enabled, the connection is opened with PRAGMA
# query_only=ON which causes SQLite to reject any statement that would
# modify the database.
READ_ONLY = os.environ.get("MCP_READ_ONLY", "true").lower() == "true"

# Hard cap on rows returned per query — prevents memory exhaustion and
# avoids flooding the AI model context window.
MAX_ROWS = min(int(os.environ.get("MCP_MAX_ROWS", "100")), 1000)

SERVER_NAME = "database-mcp"
SERVER_VERSION = "0.1.0"

# ---------------------------------------------------------------------------
# Logging
# ---------------------------------------------------------------------------

logging.basicConfig(stream=sys.stderr, level=logging.INFO, format="%(message)s")
audit_log = logging.getLogger("mcp.audit")
app_log = logging.getLogger("mcp.app")


def log_tool_call(
    call_id: str,
    tool_name: str,
    input_summary: dict,
    outcome: str,
    duration_ms: int,
    error_type: str | None = None,
) -> None:
    """Emit a structured audit log entry for a tool call."""
    entry = {
        "timestamp": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
        "call_id": call_id,
        "server": SERVER_NAME,
        "tool": tool_name,
        "input_summary": input_summary,
        "outcome": outcome,
        "duration_ms": duration_ms,
    }
    if error_type:
        entry["error_type"] = error_type
    audit_log.info(json.dumps(entry))


# ---------------------------------------------------------------------------
# Query allowlist — THE CRITICAL SECURITY CONTROL
#
# Only queries defined here can ever be executed. The AI model or caller
# supplies a query *name* and *parameters*; it never supplies raw SQL.
#
# Each entry is a dict with:
#   sql         — the SQL template; placeholders are positional ? markers
#   description — human-readable description shown by list_queries
#   params      — ordered list of parameter descriptors, each describing:
#                   name    : argument key expected from the caller
#                   type    : "table" | "column" | "int" | "str"
#                   min/max : inclusive bounds for int params
#                   maxlen  : maximum length for str params
#
# Security note: "table" and "column" typed params are validated against
# an allowlist of schema names rather than being interpolated directly —
# see validate_identifier() below. They are injected via Python string
# formatting BEFORE the query is sent to sqlite3, because SQLite's ?
# binding only works for values, not identifiers. The allowlist check
# ensures this substitution is safe.
# ---------------------------------------------------------------------------

NAMED_QUERIES: dict[str, dict[str, Any]] = {
    "count_rows": {
        "description": "Count the total number of rows in a table.",
        "params": [
            {"name": "table", "type": "table"},
        ],
        # Table name substituted after allowlist validation (not user-supplied raw SQL)
        "sql_template": "SELECT COUNT(*) AS count FROM {table}",
        "use_binding": [],  # No ? placeholders — table injected as identifier
    },
    "recent_rows": {
        "description": "Return the most recently inserted rows from a table (by rowid).",
        "params": [
            {"name": "table", "type": "table"},
            {"name": "limit", "type": "int", "min": 1, "max": 100},
        ],
        "sql_template": "SELECT * FROM {table} ORDER BY rowid DESC LIMIT ?",
        "use_binding": ["limit"],
    },
    "search_text": {
        "description": "Search rows in a table where a column matches a LIKE pattern.",
        "params": [
            {"name": "table", "type": "table"},
            {"name": "column", "type": "column"},
            {"name": "search_term", "type": "str", "maxlen": 100},
            {"name": "limit", "type": "int", "min": 1, "max": 100},
        ],
        "sql_template": "SELECT * FROM {table} WHERE {column} LIKE ? LIMIT ?",
        "use_binding": ["search_term", "limit"],
    },
    "distinct_values": {
        "description": "Return distinct values in a column, ordered alphabetically.",
        "params": [
            {"name": "table", "type": "table"},
            {"name": "column", "type": "column"},
            {"name": "limit", "type": "int", "min": 1, "max": 100},
        ],
        "sql_template": "SELECT DISTINCT {column} FROM {table} ORDER BY {column} LIMIT ?",
        "use_binding": ["limit"],
    },
}

# ---------------------------------------------------------------------------
# Database connection
# ---------------------------------------------------------------------------

# The connection is opened once at module load. check_same_thread=False
# is required because the asyncio event loop may call handlers from a
# thread different from the one that opened the connection. The server
# is single-process, single-session, so this is safe here.
_db_conn: sqlite3.Connection | None = None


def get_db() -> sqlite3.Connection:
    """Return the shared database connection, initialising it if needed."""
    global _db_conn
    if _db_conn is None:
        _db_conn = sqlite3.connect(DB_PATH, check_same_thread=False)
        _db_conn.row_factory = sqlite3.Row  # Return rows as dict-like objects

        if READ_ONLY:
            # PRAGMA query_only=ON instructs SQLite to reject any statement
            # that modifies data or schema.  This is a defence-in-depth control
            # on top of the query allowlist.
            _db_conn.execute("PRAGMA query_only=ON")
            app_log.info("Database opened in read-only mode (PRAGMA query_only=ON)")
        else:
            app_log.warning(
                "Database opened in read-write mode (MCP_READ_ONLY is not 'true')"
            )

    return _db_conn


# ---------------------------------------------------------------------------
# Identifier allowlisting — prevents SQL injection via table/column names
#
# SQLite's ? parameter binding only works for *values*, not identifiers
# (table names, column names). We therefore build an allowlist by
# querying sqlite_master at runtime and only allow names that appear there.
# Any table/column name not in the allowlist is rejected before it ever
# reaches the SQL string.
# ---------------------------------------------------------------------------

# System table prefix — always excluded from the allowlist
_SYSTEM_TABLE_PREFIX = "sqlite_"


def get_allowed_tables() -> set[str]:
    """Return the set of non-system user table names from the database."""
    conn = get_db()
    rows = conn.execute(
        "SELECT name FROM sqlite_master WHERE type='table' AND name NOT LIKE 'sqlite_%'"
    ).fetchall()
    return {row["name"] for row in rows}


def get_allowed_columns(table: str) -> set[str]:
    """Return the set of column names for a validated table."""
    conn = get_db()
    # table has already been validated by validate_identifier before this call
    rows = conn.execute(f"PRAGMA table_info({table})").fetchall()  # noqa: S608
    return {row["name"] for row in rows}


def validate_identifier(value: str, kind: str, *, table_ctx: str | None = None) -> str:
    """
    Validate a table or column name against the live database schema.

    This is the critical guard that prevents SQL injection via identifier
    substitution. It raises ValueError if the name is not in the allowlist.

    Args:
        value      : The caller-supplied name.
        kind       : "table" or "column".
        table_ctx  : For column validation, the table the column belongs to
                     (must already be validated).

    Returns the validated name unchanged.
    """
    if not isinstance(value, str) or not value:
        raise ValueError(f"'{kind}' must be a non-empty string")

    if kind == "table":
        allowed = get_allowed_tables()
        if value not in allowed:
            raise ValueError(
                f"Unknown or disallowed table: {value!r}. "
                f"Use list_tables to see available tables."
            )
    elif kind == "column":
        if table_ctx is None:
            raise ValueError("table_ctx is required for column validation")
        allowed = get_allowed_columns(table_ctx)
        if value not in allowed:
            raise ValueError(
                f"Unknown or disallowed column: {value!r} for table {table_ctx!r}. "
                f"Use describe_table to see available columns."
            )
    else:
        raise ValueError(f"Unknown identifier kind: {kind!r}")

    return value


# ---------------------------------------------------------------------------
# Parameter validation helpers
# ---------------------------------------------------------------------------


def validate_query_params(
    query_def: dict[str, Any],
    arguments: dict[str, Any],
) -> dict[str, Any]:
    """
    Validate caller-supplied parameters against the query's param spec.

    Returns a dict of validated values keyed by param name.
    Raises ValueError for any missing or invalid parameter.
    """
    validated: dict[str, Any] = {}
    table_ctx: str | None = None  # tracks the validated table name for column checks

    for param in query_def["params"]:
        name = param["name"]
        ptype = param["type"]
        raw = arguments.get(name)

        if raw is None:
            raise ValueError(f"Missing required parameter: {name!r}")

        if ptype == "table":
            validated[name] = validate_identifier(raw, "table")
            table_ctx = validated[name]

        elif ptype == "column":
            validated[name] = validate_identifier(raw, "column", table_ctx=table_ctx)

        elif ptype == "int":
            if not isinstance(raw, int):
                raise ValueError(f"Parameter {name!r} must be an integer, got {type(raw).__name__}")
            lo = param.get("min", 1)
            hi = param.get("max", MAX_ROWS)
            if not (lo <= raw <= hi):
                raise ValueError(
                    f"Parameter {name!r} must be between {lo} and {hi}, got {raw}"
                )
            validated[name] = raw

        elif ptype == "str":
            if not isinstance(raw, str):
                raise ValueError(f"Parameter {name!r} must be a string")
            maxlen = param.get("maxlen", 256)
            if len(raw) > maxlen:
                raise ValueError(
                    f"Parameter {name!r} exceeds maximum length of {maxlen}"
                )
            validated[name] = raw

        else:
            raise ValueError(f"Unknown param type: {ptype!r}")

    return validated


# ---------------------------------------------------------------------------
# Tool schemas
# ---------------------------------------------------------------------------

LIST_QUERIES_SCHEMA: dict[str, Any] = {
    "type": "object",
    "properties": {},
    "additionalProperties": False,
}

RUN_QUERY_SCHEMA: dict[str, Any] = {
    "type": "object",
    "properties": {
        "query_name": {
            "type": "string",
            "description": "Name of the named query to execute (see list_queries).",
            "minLength": 1,
            "maxLength": 64,
        },
        "params": {
            "type": "object",
            "description": "Parameters for the named query. Keys and types depend on the query.",
        },
    },
    "required": ["query_name"],
    "additionalProperties": False,
}

LIST_TABLES_SCHEMA: dict[str, Any] = {
    "type": "object",
    "properties": {},
    "additionalProperties": False,
}

DESCRIBE_TABLE_SCHEMA: dict[str, Any] = {
    "type": "object",
    "properties": {
        "table": {
            "type": "string",
            "description": "Name of the table to describe.",
            "minLength": 1,
            "maxLength": 128,
        }
    },
    "required": ["table"],
    "additionalProperties": False,
}

# ---------------------------------------------------------------------------
# Tool implementations
# ---------------------------------------------------------------------------


def tool_list_queries(_arguments: dict) -> list[dict]:
    """Return the list of available named queries with their descriptions."""
    return [
        {
            "name": name,
            "description": qdef["description"],
            "params": [
                {k: v for k, v in p.items() if k != "type" or True}
                for p in qdef["params"]
            ],
        }
        for name, qdef in NAMED_QUERIES.items()
    ]


def tool_run_query(arguments: dict) -> dict:
    """
    Execute a named query with caller-supplied parameters.

    Security controls applied here:
    1. Query name validated against NAMED_QUERIES (allowlist).
    2. Parameters validated by validate_query_params() — type, range, and
       for table/column types, existence in the live DB schema.
    3. SQL built from the template with validated identifiers substituted;
       value parameters passed via sqlite3 ? binding (never interpolated).
    4. Row count capped at MAX_ROWS.
    """
    query_name = arguments.get("query_name")
    if not isinstance(query_name, str) or not query_name:
        raise ValueError("'query_name' must be a non-empty string")

    # Security: reject any name not in the allowlist
    query_def = NAMED_QUERIES.get(query_name)
    if query_def is None:
        raise ValueError(
            f"Unknown query: {query_name!r}. Use list_queries to see available queries."
        )

    raw_params = arguments.get("params") or {}
    if not isinstance(raw_params, dict):
        raise ValueError("'params' must be an object")

    # Validate all parameters (type checks, range checks, allowlist checks)
    validated = validate_query_params(query_def, raw_params)

    # Build the SQL: substitute validated identifiers into the template.
    # Only "table" and "column" typed params go here; they have been
    # checked against the live schema above.
    identifier_subs = {
        p["name"]: validated[p["name"]]
        for p in query_def["params"]
        if p["type"] in ("table", "column")
    }
    sql = query_def["sql_template"].format(**identifier_subs)

    # Collect value bindings in the order the ? placeholders appear in the SQL
    bindings = tuple(validated[key] for key in query_def["use_binding"])

    conn = get_db()
    cursor = conn.execute(sql, bindings)

    # Cap rows returned — defence against queries that might return too much
    rows = cursor.fetchmany(MAX_ROWS)
    columns = [description[0] for description in cursor.description]
    row_dicts = [dict(zip(columns, row)) for row in rows]

    return {
        "query": query_name,
        "params": {k: v for k, v in validated.items() if k != "search_term"},
        "row_count": len(row_dicts),
        "max_rows": MAX_ROWS,
        "rows": row_dicts,
    }


def tool_list_tables(_arguments: dict) -> list[str]:
    """
    Return the names of all non-system tables in the database.

    System tables (those whose names start with 'sqlite_') are excluded
    to avoid leaking internal SQLite metadata.
    """
    return sorted(get_allowed_tables())


def tool_describe_table(arguments: dict) -> dict:
    """
    Return column names and types for a named table.

    The table name is validated against the live schema — only tables
    that exist in the database and are not system tables can be described.
    """
    table = arguments.get("table")
    if not isinstance(table, str) or not table:
        raise ValueError("'table' must be a non-empty string")

    # Validate the table name against the live schema allowlist
    validate_identifier(table, "table")

    conn = get_db()
    rows = conn.execute(f"PRAGMA table_info({table})").fetchall()  # noqa: S608

    if not rows:
        raise ValueError(f"Table {table!r} not found or has no columns")

    columns = [
        {
            "name": row["name"],
            "type": row["type"],
            "not_null": bool(row["notnull"]),
            "primary_key": bool(row["pk"]),
        }
        for row in rows
    ]
    return {"table": table, "columns": columns}


# ---------------------------------------------------------------------------
# Server setup
# ---------------------------------------------------------------------------

TOOLS = [
    Tool(
        name="list_queries",
        description=(
            "List all available named queries and their descriptions. "
            "Only these queries can be executed — no raw SQL is accepted."
        ),
        inputSchema=LIST_QUERIES_SCHEMA,
    ),
    Tool(
        name="run_query",
        description=(
            "Execute a named query by name, supplying the required parameters. "
            "Parameters are validated against the query definition. "
            "Results are capped at MCP_MAX_ROWS rows."
        ),
        inputSchema=RUN_QUERY_SCHEMA,
    ),
    Tool(
        name="list_tables",
        description="List all non-system tables available in the database.",
        inputSchema=LIST_TABLES_SCHEMA,
    ),
    Tool(
        name="describe_table",
        description=(
            "Show the column names and types for a named table. "
            "The table name must exist in the database."
        ),
        inputSchema=DESCRIBE_TABLE_SCHEMA,
    ),
]

TOOL_HANDLERS: dict[str, Any] = {
    "list_queries": tool_list_queries,
    "run_query": tool_run_query,
    "list_tables": tool_list_tables,
    "describe_table": tool_describe_table,
}

server = Server(SERVER_NAME)


@server.list_tools()
async def handle_list_tools(request: ListToolsRequest) -> ListToolsResult:
    return ListToolsResult(tools=TOOLS)


@server.call_tool()
async def handle_call_tool(request: CallToolRequest) -> CallToolResult:
    call_id = str(uuid.uuid4())
    tool_name = request.params.name
    arguments = request.params.arguments or {}
    start = time.monotonic()
    outcome = "success"
    error_type = None

    # Build a safe summary for audit logging (never log raw user data in full)
    input_summary = {
        k: (v[:80] + "..." if isinstance(v, str) and len(v) > 80 else v)
        for k, v in arguments.items()
        if k != "params"  # params logged separately to avoid nesting issues
    }
    if "params" in arguments and isinstance(arguments["params"], dict):
        input_summary["params"] = {
            pk: (pv[:80] + "..." if isinstance(pv, str) and len(pv) > 80 else pv)
            for pk, pv in arguments["params"].items()
        }

    try:
        handler = TOOL_HANDLERS.get(tool_name)
        if handler is None:
            raise ValueError(f"Unknown tool: {tool_name!r}")

        result = handler(arguments)

        if isinstance(result, str):
            content_text = result
        else:
            content_text = json.dumps(result, indent=2)

        return CallToolResult(content=[TextContent(type="text", text=content_text)])

    except ValueError as exc:
        outcome = "error"
        error_type = "ValueError"
        return CallToolResult(
            content=[TextContent(type="text", text=f"Error: {exc}")],
            isError=True,
        )
    except sqlite3.OperationalError as exc:
        outcome = "error"
        error_type = "sqlite3.OperationalError"
        # Log the DB error server-side; return a generic message to caller
        app_log.error("Database error in tool '%s': %s", tool_name, exc)
        return CallToolResult(
            content=[TextContent(type="text", text="Error: Database operation failed.")],
            isError=True,
        )
    except Exception:
        outcome = "error"
        error_type = "Exception"
        app_log.exception("Unexpected error in tool '%s'", tool_name)
        return CallToolResult(
            content=[TextContent(type="text", text="An unexpected error occurred.")],
            isError=True,
        )
    finally:
        duration_ms = int((time.monotonic() - start) * 1000)
        log_tool_call(
            call_id=call_id,
            tool_name=tool_name,
            input_summary=input_summary,
            outcome=outcome,
            duration_ms=duration_ms,
            error_type=error_type,
        )


# ---------------------------------------------------------------------------
# Demo database seed
#
# If the database file does not exist, create it and populate it with
# sample data so the server works out of the box.
# ---------------------------------------------------------------------------

_SEED_SQL = """
CREATE TABLE IF NOT EXISTS products (
    id      INTEGER PRIMARY KEY AUTOINCREMENT,
    name    TEXT NOT NULL,
    category TEXT NOT NULL,
    price   REAL NOT NULL
);

CREATE TABLE IF NOT EXISTS orders (
    id          INTEGER PRIMARY KEY AUTOINCREMENT,
    product_id  INTEGER NOT NULL,
    quantity    INTEGER NOT NULL,
    customer    TEXT NOT NULL,
    created_at  TEXT NOT NULL
);

INSERT OR IGNORE INTO products (id, name, category, price) VALUES
    (1, 'Laptop',     'Electronics', 999.99),
    (2, 'Keyboard',   'Electronics', 79.99),
    (3, 'Desk Chair', 'Furniture',   299.00),
    (4, 'Monitor',    'Electronics', 349.00),
    (5, 'Notebook',   'Stationery',  4.99);

INSERT OR IGNORE INTO orders (id, product_id, quantity, customer, created_at) VALUES
    (1, 1, 2, 'alice@example.com', '2024-01-10T09:00:00Z'),
    (2, 3, 1, 'bob@example.com',   '2024-01-11T14:30:00Z'),
    (3, 2, 5, 'alice@example.com', '2024-01-12T11:15:00Z'),
    (4, 4, 1, 'carol@example.com', '2024-01-13T16:45:00Z'),
    (5, 5, 10,'bob@example.com',   '2024-01-14T08:00:00Z');
"""


def _seed_demo_db() -> None:
    """Populate the database with demo data if it does not already contain it."""
    # Only seed if the DB was just created (products table absent)
    conn = sqlite3.connect(DB_PATH)
    try:
        existing = conn.execute(
            "SELECT name FROM sqlite_master WHERE type='table' AND name='products'"
        ).fetchone()
        if existing is None:
            conn.executescript(_SEED_SQL)
            conn.commit()
            app_log.info("Demo database seeded at %s", DB_PATH)
    finally:
        conn.close()


# ---------------------------------------------------------------------------
# Entry point
# ---------------------------------------------------------------------------


async def main() -> None:
    app_log.info("Starting %s v%s", SERVER_NAME, SERVER_VERSION)
    app_log.info(
        "DB: %s | read_only: %s | max_rows: %d",
        DB_PATH,
        READ_ONLY,
        MAX_ROWS,
    )

    # Seed the demo database before opening the shared read-only connection
    _seed_demo_db()

    # Prime the shared connection (and set PRAGMA query_only if needed)
    get_db()

    async with stdio_server() as (read_stream, write_stream):
        await server.run(
            read_stream, write_stream, server.create_initialization_options()
        )


if __name__ == "__main__":
    import asyncio

    asyncio.run(main())
