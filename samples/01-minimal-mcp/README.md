# Sample 01: Minimal Secure MCP

A minimal MCP server implementation demonstrating foundational security controls. Start here before looking at more complex samples.

## What It Does

Exposes two tools:
- `echo` — returns the input string (demonstrates input validation)
- `get_info` — returns static server information (demonstrates structured output)

## Security Controls Demonstrated

| Control | Implementation |
|---------|---------------|
| Input schema validation | Strict JSON schemas with `additionalProperties: false` |
| Input size limits | Maximum string length enforced |
| Structured error responses | No internal details in error messages |
| Audit logging | Every tool call logged with context |
| Graceful error handling | Unexpected inputs handled without crash |

## Requirements

```
mcp>=1.0.0
```

## Running

```bash
pip install -r requirements.txt
python server.py
```

## Testing

```bash
pip install pytest pytest-asyncio
pytest test_server.py -v
```
