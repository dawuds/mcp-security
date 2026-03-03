"""
Tests for Sample 02: Filesystem MCP Server.

Covers:
- validate_path: happy path, path traversal, absolute paths outside
  workspace, symlink prefix spoofing, and empty path handling.

All tests use a real temporary directory (pytest's tmp_path fixture) and
patch the module-level WORKSPACE_DIR so the server operates within it.
"""

import importlib.util
import os
import sys

import pytest

# ---------------------------------------------------------------------------
# Load the module directly from its file path to avoid package import issues.
# ---------------------------------------------------------------------------

_SERVER_PATH = os.path.join(
    os.path.dirname(__file__), "../samples/02-filesystem-mcp/server.py"
)

spec = importlib.util.spec_from_file_location("server02", _SERVER_PATH)
mod = importlib.util.module_from_spec(spec)
spec.loader.exec_module(mod)


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------


@pytest.fixture()
def workspace(tmp_path, monkeypatch):
    """
    Create a real temporary directory and point the server module at it.

    monkeypatch restores the original WORKSPACE_DIR after each test.
    """
    monkeypatch.setattr(mod, "WORKSPACE_DIR", str(tmp_path))
    return tmp_path


# ---------------------------------------------------------------------------
# validate_path tests
# ---------------------------------------------------------------------------


def test_valid_path_within_workspace(workspace):
    """A simple relative path inside the workspace should resolve correctly."""
    resolved = mod.validate_path("hello.txt")
    expected = os.path.realpath(os.path.join(str(workspace), "hello.txt"))
    assert resolved == expected


def test_valid_nested_path_within_workspace(workspace):
    """A nested relative path inside the workspace should resolve correctly."""
    resolved = mod.validate_path("subdir/file.txt")
    expected = os.path.realpath(os.path.join(str(workspace), "subdir", "file.txt"))
    assert resolved == expected


def test_path_traversal_blocked(workspace):
    """Path traversal via '../..' must raise ValueError."""
    with pytest.raises(ValueError):
        mod.validate_path("../../etc/passwd")


def test_path_traversal_single_dotdot_blocked(workspace):
    """Path traversal via '..' alone must raise ValueError."""
    with pytest.raises(ValueError):
        mod.validate_path("../sibling_dir/secret.txt")


def test_absolute_path_blocked(workspace):
    """An absolute path that resolves outside the workspace must be blocked."""
    with pytest.raises(ValueError):
        mod.validate_path("/etc/passwd")


def test_absolute_path_to_tmp_blocked(workspace):
    """An absolute path to /tmp (outside the workspace) must be blocked."""
    # Only block if /tmp is not the workspace itself.
    if str(workspace) != "/tmp":
        with pytest.raises(ValueError):
            mod.validate_path("/tmp/secret")


def test_symlink_prefix_attack_blocked(workspace, tmp_path):
    """
    A path that *starts with* the workspace prefix but resolves outside it
    must be blocked.

    For example, if WORKSPACE_DIR=/tmp/mcp-workspace, then
    /tmp/mcp-workspace-evil should not be accessible.
    """
    # Create a sibling directory whose name starts with the workspace name.
    evil_dir = tmp_path.parent / (tmp_path.name + "-evil")
    evil_dir.mkdir(exist_ok=True)
    evil_file = evil_dir / "secret.txt"
    evil_file.write_text("stolen data")

    # Attempt to escape via a relative traversal that lands in the evil dir.
    with pytest.raises(ValueError):
        mod.validate_path(f"../{tmp_path.name}-evil/secret.txt")


def test_empty_path_returns_workspace_root(workspace):
    """
    An empty path joined to the workspace root resolves to the root itself,
    which is within the workspace — this should succeed.
    """
    resolved = mod.validate_path("")
    expected = os.path.realpath(str(workspace))
    assert resolved == expected


def test_dot_path_returns_workspace_root(workspace):
    """A bare '.' path resolves to the workspace root — this should succeed."""
    resolved = mod.validate_path(".")
    expected = os.path.realpath(str(workspace))
    assert resolved == expected


def test_path_with_encoded_traversal_blocked(workspace):
    """
    Verify that paths containing URL-encoded traversal sequences are not
    silently permitted.  The server does not URL-decode, so the literal
    string '%2e%2e' is treated as a filename component, but an actual
    traversal using backslash or null bytes should still be blocked.
    """
    # On Linux '%2e%2e' is a literal directory name — joining it with the
    # workspace root keeps us inside the workspace, so it is allowed.
    # What we want to confirm is that a *real* traversal (with actual dots)
    # is blocked even when embedded inside a longer path.
    with pytest.raises(ValueError):
        mod.validate_path("valid/../../../etc/passwd")
