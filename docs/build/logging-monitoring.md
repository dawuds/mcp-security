# Logging & Monitoring for MCP Servers

MCP tool calls create a blind spot in traditional security monitoring. This guide covers what to log, how to structure it, and how to detect anomalies.

---

## Why MCP Logging Is Different

In a traditional web app, every action leaves a trace in request logs, application logs, and database audit logs. MCP tool calls:
- Are often invoked autonomously by the AI model (no direct user HTTP request)
- May chain multiple tool calls in a single AI turn
- Carry implicit context (the AI's reasoning) that isn't visible in logs
- Cross trust boundaries — from the AI model into backend systems

Without explicit logging, a complete MCP session can be invisible.

---

## What to Log

### Minimum Required (Every Tool Call)

| Field | Description |
|-------|-------------|
| `timestamp` | ISO 8601, UTC |
| `session_id` | Unique ID for the MCP session |
| `call_id` | Unique ID for this specific tool call |
| `tool_name` | Name of the tool invoked |
| `client_id` | Identity of the MCP host/client |
| `user_id` | User identity if available |
| `input_summary` | Sanitized summary of inputs (see below) |
| `outcome` | `success` / `error` / `denied` |
| `duration_ms` | Time taken to execute |

### Recommended Additional Fields

| Field | Description |
|-------|-------------|
| `output_summary` | Sanitized summary of what was returned |
| `resource_accessed` | Specific resource (file path, table name, URL) |
| `error_type` | Error class if outcome is `error` |
| `ip_address` | For remote MCP servers |

---

## Structured Log Format

Use structured JSON for machine-parseable audit trails:

```json
{
  "timestamp": "2026-03-04T12:34:56.789Z",
  "session_id": "sess_a1b2c3d4",
  "call_id": "call_e5f6g7h8",
  "tool_name": "read_file",
  "client_id": "claude-desktop-v1.2",
  "user_id": "user_42",
  "input_summary": {"path": "/workspaces/user_42/report.txt"},
  "resource_accessed": "/workspaces/user_42/report.txt",
  "outcome": "success",
  "duration_ms": 12,
  "output_summary": {"size_bytes": 4096, "truncated": false}
}
```

---

## Implementation Pattern (Python)

```python
import logging
import json
import time
import uuid
from functools import wraps

audit_logger = logging.getLogger("mcp.audit")

def audit_tool_call(tool_name: str):
    """Decorator that logs every invocation of an MCP tool."""
    def decorator(func):
        @wraps(func)
        def wrapper(*args, context: RequestContext, **kwargs):
            call_id = str(uuid.uuid4())
            start = time.monotonic()
            outcome = "success"
            error_type = None

            # Sanitize inputs for logging (remove secrets, truncate large values)
            safe_kwargs = sanitize_for_logging(kwargs)

            try:
                result = func(*args, context=context, **kwargs)
                return result
            except PermissionError as e:
                outcome = "denied"
                error_type = "PermissionError"
                raise
            except Exception as e:
                outcome = "error"
                error_type = type(e).__name__
                raise
            finally:
                duration_ms = int((time.monotonic() - start) * 1000)
                audit_logger.info(json.dumps({
                    "timestamp": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
                    "call_id": call_id,
                    "tool_name": tool_name,
                    "session_id": context.session_id,
                    "user_id": context.user_id,
                    "input_summary": safe_kwargs,
                    "outcome": outcome,
                    "error_type": error_type,
                    "duration_ms": duration_ms,
                }))
        return wrapper
    return decorator


def sanitize_for_logging(data: dict) -> dict:
    """Remove sensitive values and truncate large ones for safe logging."""
    SENSITIVE_KEYS = {"password", "token", "secret", "key", "credential"}
    result = {}
    for k, v in data.items():
        if any(s in k.lower() for s in SENSITIVE_KEYS):
            result[k] = "[REDACTED]"
        elif isinstance(v, str) and len(v) > 500:
            result[k] = v[:500] + "...[truncated]"
        else:
            result[k] = v
    return result
```

---

## What NOT to Log

- Plaintext credentials, API keys, tokens — redact these
- Full file contents returned by read tools (log metadata, not content)
- Full request/response bodies if they may contain PII — log summaries
- Stack traces in audit logs (fine in application logs, but separate streams)

---

## Retention

| Data Type | Suggested Retention |
|-----------|---------------------|
| Audit logs (tool calls) | 1 year minimum for compliance |
| Error logs | 90 days |
| Debug logs | 7-30 days |

Align with your organization's data retention policy and applicable regulations (GDPR, HIPAA, SOC 2, etc.).

---

## Detection: What to Alert On

Configure alerts for these patterns:

| Pattern | Potential Indicator |
|---------|---------------------|
| High tool call volume per session | Agentic loop gone wrong, DoS |
| Repeated authorization failures | Probing / privilege escalation attempt |
| Tool calls to unusual resources | Prompt injection success |
| Sequences: read → send/write | Data exfiltration |
| Path traversal patterns in inputs | Exploitation attempt |
| Tool calls at unusual hours | Compromised session |
| Error spikes on a specific tool | Input fuzzing or misconfiguration |

---

## Forwarding to SIEM

For centralized visibility, forward MCP audit logs to your SIEM (Splunk, Elastic, Sentinel, etc.):

```python
import logging
from logging.handlers import SysLogHandler

# Forward to syslog → SIEM
syslog_handler = SysLogHandler(address=("siem.internal", 514))
syslog_handler.setFormatter(logging.Formatter("%(message)s"))
audit_logger.addHandler(syslog_handler)
```

Or use a file-based log pipeline (Filebeat, Fluentd) to ship logs from the MCP server host.

---

## Related

- [Secure Design Principles](secure-design.md)
- [Threat Model: T6 — Lack of Audit Trail](../03-threat-model.md#t6--lack-of-audit-trail)
- [Audit Methodology](../audit/audit-methodology.md)
