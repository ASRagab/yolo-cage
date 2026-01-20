"""Path translation between agent and dispatcher filesystems."""

import os.path

from .config import WORKSPACE_ROOT

# Agent's workspace path (matches pod mount point)
AGENT_WORKSPACE = "/home/dev/workspace"


class InvalidPathError(Exception):
    """Raised when a path doesn't match the expected workspace prefix."""
    pass


def translate_cwd(agent_cwd: str, branch: str) -> str:
    """
    Translate agent's cwd to dispatcher's filesystem path.

    Agent sees /home/dev/workspace, dispatcher has /workspaces/{branch}.
    Raises InvalidPathError if the path doesn't match expected workspace prefix
    or attempts path traversal via '..'.
    """
    # Normalize path to resolve any '..' components
    normalized = os.path.normpath(agent_cwd)

    if normalized == AGENT_WORKSPACE:
        return f"{WORKSPACE_ROOT}/{branch}"
    if normalized.startswith(AGENT_WORKSPACE + "/"):
        relative = normalized[len(AGENT_WORKSPACE) + 1:]
        # Double-check relative path doesn't escape (belt and suspenders)
        if ".." in relative:
            raise InvalidPathError(f"Path traversal not allowed: {agent_cwd}")
        return f"{WORKSPACE_ROOT}/{branch}/{relative}"
    raise InvalidPathError(f"Path must be within {AGENT_WORKSPACE}, got: {agent_cwd}")
