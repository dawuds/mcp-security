# What is Model Context Protocol (MCP)?

## Overview

**Model Context Protocol (MCP)** is an open protocol developed by Anthropic that standardizes how AI models communicate with external tools, data sources, and services. Think of it as a universal interface layer between an AI model (the "client") and the external world (MCP "servers").

MCP replaces ad-hoc tool integration patterns with a consistent, inspectable protocol — which has significant implications for both capability and security.

---

## Architecture

```
┌─────────────────────────────────────────────────────┐
│                   MCP Host / Client                 │
│  (Claude Desktop, Claude Code, custom AI app, etc.) │
│                                                     │
│   ┌─────────────┐     ┌──────────────────────────┐ │
│   │  AI Model   │────▶│    MCP Client Library    │ │
│   │  (Claude)   │◀────│  (protocol handling)     │ │
│   └─────────────┘     └───────────┬──────────────┘ │
└───────────────────────────────────┼────────────────┘
                                    │ MCP Protocol
                     ┌──────────────┴──────────────┐
                     │                             │
             ┌───────▼───────┐           ┌─────────▼─────────┐
             │  MCP Server A │           │   MCP Server B    │
             │  (filesystem) │           │  (external API)   │
             └───────┬───────┘           └─────────┬─────────┘
                     │                             │
             ┌───────▼───────┐           ┌─────────▼─────────┐
             │  Local Files  │           │   External APIs   │
             └───────────────┘           └───────────────────┘
```

### Key Components

| Component | Role |
|-----------|------|
| **MCP Host** | The application running the AI model (e.g., Claude Desktop, Claude Code) |
| **MCP Client** | The protocol client embedded in the host that manages server connections |
| **MCP Server** | A process exposing tools, resources, or prompts to the AI model |

---

## What MCP Servers Expose

MCP servers can expose three primitive types:

### 1. Tools
Functions the AI model can call to take actions or retrieve data.
```json
{
  "name": "read_file",
  "description": "Read a file from the local filesystem",
  "inputSchema": {
    "type": "object",
    "properties": {
      "path": { "type": "string" }
    },
    "required": ["path"]
  }
}
```
> **Security note:** Tool calls are the primary attack surface. The AI model decides when and how to call tools based on context — including content returned by prior tool calls.

### 2. Resources
Data sources the AI model can read (files, database records, API responses, etc.).

### 3. Prompts
Pre-defined prompt templates that can be injected into the model's context.

---

## Transport Mechanisms

MCP supports two transports:

| Transport | Use Case | Security Implications |
|-----------|----------|-----------------------|
| **stdio** | Local MCP servers (same machine) | Process isolation, no network exposure |
| **HTTP + SSE** | Remote MCP servers | Network exposure, requires auth, TLS |

---

## Protocol Flow

A typical tool call sequence:

1. Host starts MCP server and initializes connection
2. Host requests list of available tools (`tools/list`)
3. AI model decides to call a tool based on user request
4. Host sends `tools/call` request to MCP server
5. MCP server executes the tool and returns result
6. Result is injected into AI model's context
7. AI model processes result and continues

The key security implication: **the content returned by step 6 is trusted by the AI model the same way user input is** — making it a vector for prompt injection.

---

## MCP vs. Traditional API Integration

| Aspect | Traditional API call | MCP Tool call |
|--------|---------------------|---------------|
| Who decides to call it | Developer code | AI model |
| Input construction | Deterministic | AI-generated |
| Result handling | Developer code | AI model interprets |
| Audit visibility | Standard logs | Often invisible |
| Attack surface | Server-side | Server + AI model |

The shift from deterministic to AI-driven tool invocation fundamentally changes the security model.

---

## Further Reading

- [Anthropic MCP Documentation](https://modelcontextprotocol.io)
- [MCP Specification](https://spec.modelcontextprotocol.io)
- [Security Model](02-security-model.md)
- [Threat Model](03-threat-model.md)
