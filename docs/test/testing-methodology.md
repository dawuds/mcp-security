# MCP Testing Methodology

Security testing for MCP servers combines traditional application security testing with AI-specific techniques. This guide covers approaches, tools, and test design.

---

## Types of MCP Security Testing

| Type | Focus | When |
|------|-------|------|
| Unit testing | Individual input validators, auth functions | During development |
| Integration testing | MCP server behavior with real inputs | During development + CI |
| Security regression tests | Known vulnerability classes | CI pipeline |
| Adversarial/manual testing | Creative attacks, prompt injection | Before release, periodically |
| Automated fuzzing | Edge cases and unexpected inputs | CI pipeline |

---

## Test Environment Setup

Set up an isolated test environment:

```bash
# Install MCP SDK
pip install mcp

# Install test dependencies
pip install pytest pytest-asyncio httpx

# Run the MCP server in test mode (stdio)
python your_mcp_server.py
```

For testing with an actual AI model:
- Use a test Claude API key
- Consider using a smaller/cheaper model for automated test suites
- Log all model-tool interactions for analysis

---

## Test Client (Python)

A basic test client for directly testing MCP server behavior without an AI model:

```python
import asyncio
import json
from mcp import ClientSession, StdioServerParameters
from mcp.client.stdio import stdio_client

async def test_mcp_server(server_script: str):
    server_params = StdioServerParameters(
        command="python",
        args=[server_script]
    )

    async with stdio_client(server_params) as (read, write):
        async with ClientSession(read, write) as session:
            await session.initialize()

            # List tools
            tools = await session.list_tools()
            print("Available tools:", [t.name for t in tools.tools])

            # Call a tool directly
            result = await session.call_tool(
                "read_file",
                arguments={"path": "../../etc/passwd"}  # Test path traversal
            )
            print("Result:", result)

asyncio.run(test_mcp_server("your_server.py"))
```

---

## Test Case Categories

### Category 1: Authentication Tests

| Test | Expected Result | Fail Condition |
|------|----------------|----------------|
| Call tool without auth token | 401 / connection refused | Tool executes or returns data |
| Call tool with expired token | 401 | Tool executes |
| Call tool with invalid signature | 401 | Tool executes |
| Call tool with wrong audience claim | 401 | Tool executes |

### Category 2: Input Validation Tests

| Test | Expected Result | Fail Condition |
|------|----------------|----------------|
| Path traversal (`../../etc/passwd`) | Error: path not allowed | File content returned |
| Absolute path (`/etc/shadow`) | Error: path not allowed | File content returned |
| SSRF URL (`http://169.254.169.254`) | Error: URL not allowed | Response returned |
| SQL injection in query field | Error or sanitized query | SQL error or data returned |
| Oversized input (100,000 char string) | Error: input too large | Server hangs or crashes |
| Extra/unexpected parameters | Error: validation failed | Parameters silently ignored |

### Category 3: Prompt Injection Tests

See [prompt-injection-tests.md](prompt-injection-tests.md) for detailed test cases.

### Category 4: Authorization Tests

| Test | Expected Result | Fail Condition |
|------|----------------|----------------|
| User A accesses User B's resource | 403 | Data returned |
| Standard user calls admin tool | 403 | Tool executes |
| Write tool called with read-only token | 403 | Write executes |

---

## Automated Test Suite Structure

```
tests/
├── test_authentication.py      # Auth bypass tests
├── test_authorization.py       # Privilege escalation tests
├── test_input_validation.py    # Path traversal, SSRF, injection
├── test_rate_limiting.py       # DoS and rate limit tests
├── test_tool_schemas.py        # Schema validation tests
└── test_prompt_injection.py    # AI-in-the-loop prompt injection tests
```

---

## Fuzzing MCP Inputs

Fuzz tool call inputs to discover unexpected behavior:

```python
import pytest
import hypothesis
from hypothesis import given, strategies as st

@given(
    path=st.text(min_size=0, max_size=10000)
)
def test_read_file_fuzz(path: str):
    """Fuzzing should never cause the server to crash or return /etc contents."""
    try:
        result = call_read_file_tool(path)
        # If we get a result, it should not contain sensitive content
        assert "/etc/passwd" not in str(result)
        assert "root:x:0:0" not in str(result)
    except (ValueError, PermissionError):
        # Expected — validation should raise these
        pass
    except Exception as e:
        # Unexpected exceptions are test failures
        pytest.fail(f"Unexpected exception for input {path!r}: {e}")
```

---

## CI/CD Integration

Add security tests to your CI pipeline:

```yaml
# .github/workflows/security-tests.yml
name: Security Tests

on: [push, pull_request]

jobs:
  security:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - name: Install dependencies
        run: pip install -r requirements.txt -r requirements-dev.txt
      - name: Run security tests
        run: pytest tests/test_authentication.py tests/test_input_validation.py tests/test_authorization.py -v
      - name: Dependency audit
        run: pip-audit
```

---

## Testing Checklist

- [ ] Authentication tests: all bypass scenarios tested
- [ ] Path traversal: multiple encoding variants tested
- [ ] SSRF: internal IPs, metadata endpoints, localhost tested
- [ ] Injection: SQL, shell, template injection tested
- [ ] Schema validation: extra fields, wrong types, missing required fields tested
- [ ] Authorization: horizontal and vertical privilege escalation tested
- [ ] Rate limiting: high-volume calls tested
- [ ] Oversized inputs: server handles gracefully without crash
- [ ] Error messages: no sensitive internal details exposed
- [ ] Prompt injection: AI-in-the-loop tests run

---

## Related

- [Test Cases](test-cases.md)
- [Prompt Injection Tests](prompt-injection-tests.md)
- [Assessment Methodology](../assess/assessment-methodology.md)
