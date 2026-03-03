"""
Tests for Sample 03: API Gateway MCP Server.

Covers:
- validate_url: HTTPS/HTTP allowed, file scheme blocked, private IP
  ranges blocked (10.x, 192.168.x, loopback), AWS metadata endpoint
  blocked, hostname-based cloud metadata endpoints blocked.
- sanitize_headers: Authorization and Cookie stripped, safe headers
  pass through unchanged.
- check_rate_limit: passes up to the limit, raises ValueError on the
  call that would exceed it.
"""

import importlib.util
import os
import sys
import time

import pytest

# ---------------------------------------------------------------------------
# Load the module directly from its file path to avoid package import issues.
# ---------------------------------------------------------------------------

_SERVER_PATH = os.path.join(
    os.path.dirname(__file__), "../samples/03-api-gateway-mcp/server.py"
)

spec = importlib.util.spec_from_file_location("server03", _SERVER_PATH)
mod = importlib.util.module_from_spec(spec)
spec.loader.exec_module(mod)

# Convenience aliases
validate_url = mod.validate_url
sanitize_headers = mod.sanitize_headers
check_rate_limit = mod.check_rate_limit
RATE_LIMIT_PER_MINUTE = mod.RATE_LIMIT_PER_MINUTE


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------


@pytest.fixture(autouse=True)
def clear_rate_limit_store():
    """Reset the in-memory rate-limit store before each test."""
    mod._rate_limit_store.clear()
    yield
    mod._rate_limit_store.clear()


# ---------------------------------------------------------------------------
# validate_url — allowed schemes
# ---------------------------------------------------------------------------


def test_valid_https_url_passes():
    """HTTPS URLs pointing to public hosts should pass validation."""
    url = validate_url("https://example.com/api/data")
    assert url == "https://example.com/api/data"


def test_http_url_passes():
    """HTTP URLs pointing to public hosts should also be allowed."""
    url = validate_url("http://example.com/resource")
    assert url == "http://example.com/resource"


def test_url_with_path_and_query_passes():
    """URLs with query strings and paths on public hosts should pass."""
    url = validate_url("https://api.example.com/v1/items?page=1&limit=20")
    assert url == "https://api.example.com/v1/items?page=1&limit=20"


# ---------------------------------------------------------------------------
# validate_url — blocked schemes
# ---------------------------------------------------------------------------


def test_file_scheme_blocked():
    """file:// URLs must be rejected."""
    with pytest.raises(ValueError, match="scheme"):
        validate_url("file:///etc/passwd")


def test_ftp_scheme_blocked():
    """ftp:// URLs must be rejected."""
    with pytest.raises(ValueError, match="scheme"):
        validate_url("ftp://files.example.com/pub/data.txt")


def test_gopher_scheme_blocked():
    """gopher:// URLs must be rejected."""
    with pytest.raises(ValueError, match="scheme"):
        validate_url("gopher://example.com/")


# ---------------------------------------------------------------------------
# validate_url — private IP ranges (SSRF prevention)
# ---------------------------------------------------------------------------


def test_private_ip_10_blocked():
    """Requests to 10.x.x.x (RFC 1918 private range) must be blocked."""
    with pytest.raises(ValueError, match="private"):
        validate_url("http://10.0.0.1/internal-api")


def test_private_ip_172_16_blocked():
    """Requests to 172.16.x.x (RFC 1918 private range) must be blocked."""
    with pytest.raises(ValueError, match="private"):
        validate_url("http://172.16.0.1/admin")


def test_private_ip_192_168_blocked():
    """Requests to 192.168.x.x (RFC 1918 private range) must be blocked."""
    with pytest.raises(ValueError, match="private"):
        validate_url("http://192.168.1.1/router-admin")


def test_loopback_blocked():
    """Requests to 127.0.0.1 (loopback) must be blocked."""
    with pytest.raises(ValueError, match="private"):
        validate_url("http://127.0.0.1:8080/health")


def test_loopback_localhost_numeric_blocked():
    """Requests to 127.x.x.x variants must be blocked."""
    with pytest.raises(ValueError, match="private"):
        validate_url("http://127.255.255.255/")


# ---------------------------------------------------------------------------
# validate_url — cloud metadata endpoints
# ---------------------------------------------------------------------------


def test_aws_metadata_blocked():
    """The AWS/Azure/GCP instance metadata IP (169.254.169.254) must be blocked."""
    with pytest.raises(ValueError):
        validate_url("http://169.254.169.254/latest/meta-data/")


def test_link_local_range_blocked():
    """Any 169.254.x.x address (link-local) must be blocked."""
    with pytest.raises(ValueError, match="private"):
        validate_url("http://169.254.0.1/data")


def test_google_metadata_hostname_blocked():
    """The GCP metadata hostname must be blocked."""
    with pytest.raises(ValueError, match="not permitted"):
        validate_url("http://metadata.google.internal/computeMetadata/v1/")


def test_alibaba_metadata_blocked():
    """The Alibaba Cloud metadata IP must be blocked."""
    with pytest.raises(ValueError):
        validate_url("http://100.100.100.200/latest/meta-data/")


# ---------------------------------------------------------------------------
# sanitize_headers
# ---------------------------------------------------------------------------


def test_authorization_header_removed():
    """The Authorization header must be stripped before forwarding."""
    headers = {"Authorization": "Bearer secret-token", "Accept": "application/json"}
    result = sanitize_headers(headers)
    assert "Authorization" in headers, "original dict should be unmodified"
    assert "Authorization" not in result
    assert result.get("Accept") == "application/json"


def test_authorization_header_case_insensitive_removed():
    """Authorization header removal must be case-insensitive."""
    headers = {"authorization": "Basic dXNlcjpwYXNz"}
    result = sanitize_headers(headers)
    assert "authorization" not in result


def test_cookie_header_removed():
    """The Cookie header must be stripped before forwarding."""
    headers = {"Cookie": "session=abc123", "Content-Type": "application/json"}
    result = sanitize_headers(headers)
    assert "Cookie" not in result
    assert result.get("Content-Type") == "application/json"


def test_set_cookie_header_removed():
    """The Set-Cookie header must also be stripped."""
    headers = {"Set-Cookie": "id=42; HttpOnly"}
    result = sanitize_headers(headers)
    assert "Set-Cookie" not in result


def test_x_api_key_removed():
    """The X-Api-Key header must be stripped before forwarding."""
    headers = {"X-Api-Key": "super-secret", "X-Request-ID": "req-001"}
    result = sanitize_headers(headers)
    assert "X-Api-Key" not in result
    assert result.get("X-Request-ID") == "req-001"


def test_safe_headers_pass_through():
    """Headers that are not in the blocklist should be forwarded unchanged."""
    headers = {
        "Accept": "application/json",
        "Content-Type": "application/json",
        "X-Request-ID": "abc-123",
        "User-Agent": "mcp-client/1.0",
    }
    result = sanitize_headers(headers)
    assert result == headers


def test_sanitize_headers_none_returns_empty():
    """sanitize_headers(None) should return an empty dict."""
    result = sanitize_headers(None)
    assert result == {}


def test_sanitize_headers_empty_returns_empty():
    """sanitize_headers({}) should return an empty dict."""
    result = sanitize_headers({})
    assert result == {}


def test_sanitize_headers_drops_non_string_values():
    """Header values that are not strings should be filtered out."""
    headers = {"Accept": "application/json", "X-Count": 42}
    result = sanitize_headers(headers)
    assert "Accept" in result
    assert "X-Count" not in result


# ---------------------------------------------------------------------------
# check_rate_limit
# ---------------------------------------------------------------------------


def test_rate_limit_allows_up_to_limit():
    """Calls up to RATE_LIMIT_PER_MINUTE should all succeed."""
    session = "test-session-allowed"
    for _ in range(RATE_LIMIT_PER_MINUTE):
        check_rate_limit(session)  # Should not raise


def test_rate_limit_exceeded():
    """The call that exceeds the rate limit must raise ValueError."""
    session = "test-session-exceeded"
    for _ in range(RATE_LIMIT_PER_MINUTE):
        check_rate_limit(session)

    with pytest.raises(ValueError, match="[Rr]ate limit"):
        check_rate_limit(session)  # 31st call — should fail


def test_rate_limit_different_sessions_are_independent():
    """Rate limit counters must be isolated per session ID."""
    session_a = "session-a"
    session_b = "session-b"

    # Exhaust session A's limit.
    for _ in range(RATE_LIMIT_PER_MINUTE):
        check_rate_limit(session_a)

    # Session B should still have a full budget.
    check_rate_limit(session_b)  # Should not raise


def test_rate_limit_window_expires(monkeypatch):
    """
    Calls older than 60 seconds should fall outside the window and not
    count against the rate limit.
    """
    session = "test-session-window"

    # Simulate RATE_LIMIT_PER_MINUTE calls that happened 61 seconds ago.
    old_timestamp = time.monotonic() - 61.0
    mod._rate_limit_store[session] = [old_timestamp] * RATE_LIMIT_PER_MINUTE

    # A new call should succeed because the old calls are outside the window.
    check_rate_limit(session)  # Should not raise
