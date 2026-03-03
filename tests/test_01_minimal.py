"""
Tests for Sample 01: Minimal Secure MCP Server.

Covers:
- echo tool: happy path, empty string rejection, non-string rejection,
  too-long string rejection.
- get_info tool: return type and required fields.
"""

import importlib.util
import os
import sys

import pytest

# ---------------------------------------------------------------------------
# Load the module directly from its file path to avoid package import issues.
# ---------------------------------------------------------------------------

_SERVER_PATH = os.path.join(
    os.path.dirname(__file__), "../samples/01-minimal-mcp/server.py"
)

spec = importlib.util.spec_from_file_location("server01", _SERVER_PATH)
mod = importlib.util.module_from_spec(spec)
spec.loader.exec_module(mod)

# Convenience aliases
tool_echo = mod.tool_echo
tool_get_info = mod.tool_get_info
MAX_STRING_LENGTH = mod.MAX_STRING_LENGTH


# ---------------------------------------------------------------------------
# echo tests
# ---------------------------------------------------------------------------


def test_echo_returns_message():
    """echo should return the exact message that was passed in."""
    result = tool_echo({"message": "hello"})
    assert result == "hello"


def test_echo_returns_message_unchanged():
    """echo should not modify the message in any way."""
    msg = "The quick brown fox jumps over the lazy dog."
    assert tool_echo({"message": msg}) == msg


def test_echo_rejects_empty():
    """echo should raise ValueError when message is an empty string."""
    with pytest.raises(ValueError):
        tool_echo({"message": ""})


def test_echo_rejects_non_string_int():
    """echo should raise ValueError when message is an integer."""
    with pytest.raises(ValueError):
        tool_echo({"message": 42})


def test_echo_rejects_non_string_none():
    """echo should raise ValueError when message is None."""
    with pytest.raises(ValueError):
        tool_echo({"message": None})


def test_echo_rejects_non_string_list():
    """echo should raise ValueError when message is a list."""
    with pytest.raises(ValueError):
        tool_echo({"message": ["hello"]})


def test_echo_rejects_too_long():
    """echo should raise ValueError when message exceeds MAX_STRING_LENGTH."""
    long_message = "x" * (MAX_STRING_LENGTH + 1)
    with pytest.raises(ValueError):
        tool_echo({"message": long_message})


def test_echo_accepts_exactly_max_length():
    """echo should accept a message of exactly MAX_STRING_LENGTH characters."""
    msg = "a" * MAX_STRING_LENGTH
    result = tool_echo({"message": msg})
    assert result == msg


def test_echo_rejects_missing_message_key():
    """echo should raise ValueError when the 'message' key is absent."""
    with pytest.raises(ValueError):
        tool_echo({})


# ---------------------------------------------------------------------------
# get_info tests
# ---------------------------------------------------------------------------


def test_get_info_returns_dict():
    """get_info should return a dict."""
    result = tool_get_info({})
    assert isinstance(result, dict)


def test_get_info_has_name():
    """get_info result should include a 'name' field."""
    result = tool_get_info({})
    assert "name" in result
    assert isinstance(result["name"], str)


def test_get_info_has_version():
    """get_info result should include a 'version' field."""
    result = tool_get_info({})
    assert "version" in result
    assert isinstance(result["version"], str)


def test_get_info_has_tools():
    """get_info result should include a 'tools' field listing available tools."""
    result = tool_get_info({})
    assert "tools" in result
    tools = result["tools"]
    assert isinstance(tools, list)
    assert len(tools) > 0


def test_get_info_lists_echo_and_get_info():
    """get_info should mention both 'echo' and 'get_info' in its tools list."""
    result = tool_get_info({})
    tools = result["tools"]
    assert "echo" in tools
    assert "get_info" in tools
