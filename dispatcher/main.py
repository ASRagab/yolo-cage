"""
yolo-cage Git Dispatcher

HTTP service that executes git commands on behalf of sandboxed agents.
Enforces branch restrictions and runs pre-push hooks.
"""

import json
import logging
import os
import shutil
import subprocess
from typing import Optional

from fastapi import FastAPI, Request, HTTPException
from fastapi.responses import PlainTextResponse
from pydantic import BaseModel

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s %(levelname)s %(message)s"
)
logger = logging.getLogger(__name__)

app = FastAPI(title="yolo-cage Git Dispatcher", version="0.2.0")

# Configuration (loaded from environment/config)
WORKSPACE_ROOT = os.environ.get("WORKSPACE_ROOT", "/workspaces")
GIT_USER_NAME = os.environ.get("GIT_USER_NAME", "yolo-cage")
GIT_USER_EMAIL = os.environ.get("GIT_USER_EMAIL", "yolo-cage@localhost")
GITHUB_PAT = os.environ.get("GITHUB_PAT", "")
YOLO_CAGE_VERSION = os.environ.get("YOLO_CAGE_VERSION", "0.2.0")

# Pre-push hooks configuration (JSON array of commands)
# Default: TruffleHog scanning
DEFAULT_PRE_PUSH_HOOKS = [
    "trufflehog git file://. --since-commit HEAD~10 --fail --no-update"
]
PRE_PUSH_HOOKS = json.loads(
    os.environ.get("PRE_PUSH_HOOKS", json.dumps(DEFAULT_PRE_PUSH_HOOKS))
)

# Commit message footer (can be disabled by setting to empty)
COMMIT_FOOTER = os.environ.get(
    "COMMIT_FOOTER",
    f"Built autonomously using yolo-cage v{YOLO_CAGE_VERSION}"
)


class GitRequest(BaseModel):
    """Request from git shim in sandbox pod."""
    args: list[str]
    cwd: str


class GitResponse(BaseModel):
    """Response to git shim."""
    exit_code: int
    stdout: str
    stderr: str
    message: Optional[str] = None  # yolo-cage specific messages (warnings, denials)


# In-memory branch registry: pod_ip -> branch_name
# In production, this would be backed by a ConfigMap or similar
branch_registry: dict[str, str] = {}


# Command classification
ALLOWLIST_LOCAL = {
    "add", "rm", "status", "log", "diff", "show",
    "stash", "reset", "restore", "rev-parse", "ls-files",
    "blame", "shortlog", "describe", "tag",
}

ALLOWLIST_BRANCH = {
    "branch", "checkout", "switch",
}

ALLOWLIST_MERGE = {
    "merge", "rebase", "cherry-pick",
}

ALLOWLIST_REMOTE_READ = {
    "fetch", "pull",
}

ALLOWLIST_REMOTE_WRITE = {
    "push",
}

DENYLIST_WITH_MESSAGE = {
    "remote": "yolo-cage: remote management is not permitted",
    "clone": "yolo-cage: clone is not permitted; use the provided workspace",
    "submodule": "yolo-cage: submodules are not supported",
    "credential": "yolo-cage: credential management is not permitted",
    "config": "yolo-cage: direct git configuration is not permitted.\n"
              "User identity and settings are managed via deployment configuration.",
}


def get_git_command(args: list[str]) -> Optional[str]:
    """Extract the git subcommand from args."""
    for arg in args:
        if not arg.startswith("-"):
            return arg
    return None


def get_current_branch(cwd: str) -> Optional[str]:
    """Get the current branch in the given working directory."""
    try:
        result = subprocess.run(
            ["git", "rev-parse", "--abbrev-ref", "HEAD"],
            cwd=cwd,
            capture_output=True,
            text=True,
            timeout=10,
        )
        if result.returncode == 0:
            return result.stdout.strip()
    except Exception:
        pass
    return None


def classify_command(args: list[str]) -> tuple[str, Optional[str]]:
    """
    Classify a git command and return (category, deny_message).

    Categories:
    - "local": Allowed, no restrictions
    - "branch": Allowed, may warn about switching
    - "merge": Only allowed on assigned branch
    - "remote_read": Allowed (fetch, pull)
    - "remote_write": Allowed with branch enforcement + hooks
    - "denied": Blocked with message
    - "unknown": Not recognized
    """
    cmd = get_git_command(args)
    if cmd is None:
        return "unknown", None

    if cmd in DENYLIST_WITH_MESSAGE:
        return "denied", DENYLIST_WITH_MESSAGE[cmd]

    if cmd in ALLOWLIST_LOCAL:
        return "local", None

    if cmd in ALLOWLIST_BRANCH:
        return "branch", None

    if cmd in ALLOWLIST_MERGE:
        return "merge", None

    if cmd in ALLOWLIST_REMOTE_READ:
        return "remote_read", None

    if cmd in ALLOWLIST_REMOTE_WRITE:
        return "remote_write", None

    return "unknown", None


def run_pre_push_hooks(cwd: str) -> tuple[bool, str]:
    """
    Run pre-push hooks (TruffleHog by default).

    Returns (success, output).
    """
    if not PRE_PUSH_HOOKS:
        return True, ""

    outputs = []
    for hook_cmd in PRE_PUSH_HOOKS:
        logger.info(f"Running pre-push hook: {hook_cmd}")
        try:
            result = subprocess.run(
                hook_cmd,
                shell=True,
                cwd=cwd,
                capture_output=True,
                text=True,
                timeout=120,  # 2 minute timeout per hook
            )
            if result.stdout:
                outputs.append(result.stdout)
            if result.stderr:
                outputs.append(result.stderr)

            if result.returncode != 0:
                logger.warning(f"Pre-push hook failed: {hook_cmd}")
                return False, "\n".join(outputs)
        except subprocess.TimeoutExpired:
            outputs.append(f"Hook timed out: {hook_cmd}")
            return False, "\n".join(outputs)
        except Exception as e:
            outputs.append(f"Hook failed: {hook_cmd}: {e}")
            return False, "\n".join(outputs)

    return True, "\n".join(outputs)


def get_git_env() -> dict:
    """Get environment variables for git execution."""
    env = os.environ.copy()
    env["GIT_AUTHOR_NAME"] = GIT_USER_NAME
    env["GIT_AUTHOR_EMAIL"] = GIT_USER_EMAIL
    env["GIT_COMMITTER_NAME"] = GIT_USER_NAME
    env["GIT_COMMITTER_EMAIL"] = GIT_USER_EMAIL

    # For HTTPS authentication with PAT, we use a credential helper
    # that returns the token. Git will call this when authenticating.
    if GITHUB_PAT:
        # Use the store helper configured with our credentials
        # We'll write a temporary .git-credentials file
        env["GIT_TERMINAL_PROMPT"] = "0"

    return env


def execute_git(args: list[str], cwd: str) -> tuple[int, str, str]:
    """Execute a git command and return (exit_code, stdout, stderr)."""
    env = get_git_env()

    # For commands that need auth, inject credentials into URL
    # This is a simple approach that works with HTTPS remotes
    modified_args = list(args)

    try:
        result = subprocess.run(
            ["git"] + modified_args,
            cwd=cwd,
            capture_output=True,
            text=True,
            timeout=300,  # 5 minute timeout for long operations
            env=env,
        )
        return result.returncode, result.stdout, result.stderr
    except subprocess.TimeoutExpired:
        return 1, "", "yolo-cage: git command timed out after 5 minutes"
    except Exception as e:
        return 1, "", f"yolo-cage: failed to execute git: {e}"


def execute_git_with_auth(args: list[str], cwd: str) -> tuple[int, str, str]:
    """Execute a git command that requires authentication."""
    env = get_git_env()

    # Set up credential helper that echoes our PAT
    # The helper script format is: protocol, host -> username, password
    if GITHUB_PAT:
        # Use GIT_ASKPASS to provide credentials
        askpass_script = "/tmp/git-askpass.sh"
        with open(askpass_script, "w") as f:
            f.write(f"#!/bin/bash\necho {GITHUB_PAT}\n")
        os.chmod(askpass_script, 0o700)
        env["GIT_ASKPASS"] = askpass_script
        env["GIT_TERMINAL_PROMPT"] = "0"

    try:
        result = subprocess.run(
            ["git"] + args,
            cwd=cwd,
            capture_output=True,
            text=True,
            timeout=300,
            env=env,
        )
        return result.returncode, result.stdout, result.stderr
    except subprocess.TimeoutExpired:
        return 1, "", "yolo-cage: git command timed out after 5 minutes"
    except Exception as e:
        return 1, "", f"yolo-cage: failed to execute git: {e}"
    finally:
        # Clean up askpass script
        if GITHUB_PAT and os.path.exists("/tmp/git-askpass.sh"):
            os.remove("/tmp/git-askpass.sh")


@app.get("/health")
async def health():
    """Health check endpoint."""
    return {"status": "ok"}


@app.post("/register")
async def register_pod(request: Request, branch: str):
    """
    Register a pod IP -> branch mapping.
    Called by CLI when creating a new pod.
    """
    client_ip = request.client.host
    branch_registry[client_ip] = branch
    logger.info(f"Registered pod {client_ip} for branch {branch}")
    return {"status": "registered", "ip": client_ip, "branch": branch}


@app.delete("/register")
async def deregister_pod(request: Request):
    """
    Remove a pod from the registry.
    Called by CLI when deleting a pod.
    """
    client_ip = request.client.host
    if client_ip in branch_registry:
        branch = branch_registry.pop(client_ip)
        logger.info(f"Deregistered pod {client_ip} (was branch {branch})")
        return {"status": "deregistered", "ip": client_ip}
    return {"status": "not_found", "ip": client_ip}


@app.get("/registry")
async def list_registry():
    """List all registered pods (for debugging/CLI)."""
    return {"registry": branch_registry}


@app.post("/git", response_class=PlainTextResponse)
async def handle_git(git_req: GitRequest, request: Request):
    """
    Handle a git command from a sandbox pod.

    The shim POSTs here with {"args": [...], "cwd": "..."}.
    We authenticate by source IP, enforce rules, execute, and return output.
    """
    client_ip = request.client.host
    assigned_branch = branch_registry.get(client_ip)

    if assigned_branch is None:
        logger.warning(f"Unknown pod {client_ip} attempted git operation")
        raise HTTPException(
            status_code=403,
            detail="yolo-cage: pod not registered. Contact cluster admin."
        )

    logger.info(f"Git request from {client_ip} (branch {assigned_branch}): {git_req.args}")

    # Classify the command
    category, deny_message = classify_command(git_req.args)

    # Handle denied commands
    if category == "denied":
        logger.info(f"Denied command from {client_ip}: {git_req.args}")
        return PlainTextResponse(
            content=f"{deny_message}\n",
            status_code=200,  # Return 200 so shim passes through the message
            headers={"X-Yolo-Cage-Exit-Code": "1"}
        )

    if category == "unknown":
        logger.info(f"Unknown command from {client_ip}: {git_req.args}")
        return PlainTextResponse(
            content="yolo-cage: unrecognized or disallowed git operation\n",
            status_code=200,
            headers={"X-Yolo-Cage-Exit-Code": "1"}
        )

    # For branch operations, check if switching away and warn
    message_prefix = ""
    if category == "branch":
        cmd = get_git_command(git_req.args)
        if cmd in ("checkout", "switch"):
            # Check if there's a target branch in args
            target = None
            for i, arg in enumerate(git_req.args):
                if arg in ("checkout", "switch") and i + 1 < len(git_req.args):
                    next_arg = git_req.args[i + 1]
                    if not next_arg.startswith("-"):
                        target = next_arg
                        break

            if target and target != assigned_branch:
                message_prefix = (
                    f"yolo-cage: you are now viewing branch '{target}'.\n"
                    f"Your assigned branch is '{assigned_branch}'.\n"
                    f"Commits and pushes to other branches are not permitted.\n\n"
                )

    # For merge operations, must be on assigned branch
    if category == "merge":
        current = get_current_branch(git_req.cwd)
        if current != assigned_branch:
            return PlainTextResponse(
                content=(
                    f"yolo-cage: you can only {get_git_command(git_req.args)} "
                    f"while on your assigned branch '{assigned_branch}'.\n"
                    f"Run 'git checkout {assigned_branch}' first.\n"
                ),
                status_code=200,
                headers={"X-Yolo-Cage-Exit-Code": "1"}
            )

    # For push, enforce branch and run hooks
    if category == "remote_write":
        # Check we're pushing to the right branch
        current = get_current_branch(git_req.cwd)
        if current != assigned_branch:
            return PlainTextResponse(
                content=(
                    f"yolo-cage: you can only push from your assigned branch '{assigned_branch}'.\n"
                    f"Current branch is '{current}'.\n"
                ),
                status_code=200,
                headers={"X-Yolo-Cage-Exit-Code": "1"}
            )

        # Check if pushing to a different branch
        # Simple heuristic: look for refspec in args
        for arg in git_req.args:
            if ":" in arg and not arg.startswith("-"):
                # refspec like "local:remote"
                _, remote_ref = arg.split(":", 1)
                if remote_ref and remote_ref != assigned_branch:
                    return PlainTextResponse(
                        content=f"yolo-cage: you can only push to branch '{assigned_branch}'\n",
                        status_code=200,
                        headers={"X-Yolo-Cage-Exit-Code": "1"}
                    )

        # Run pre-push hooks
        hook_success, hook_output = run_pre_push_hooks(git_req.cwd)
        if not hook_success:
            return PlainTextResponse(
                content=(
                    f"yolo-cage: push rejected by pre-push hooks\n\n{hook_output}"
                ),
                status_code=200,
                headers={"X-Yolo-Cage-Exit-Code": "1"}
            )

    # Execute the command
    # Use authenticated execution for remote operations
    if category in ("remote_read", "remote_write"):
        exit_code, stdout, stderr = execute_git_with_auth(git_req.args, git_req.cwd)
    else:
        exit_code, stdout, stderr = execute_git(git_req.args, git_req.cwd)

    # Combine output
    output = message_prefix + stdout + stderr

    return PlainTextResponse(
        content=output,
        headers={"X-Yolo-Cage-Exit-Code": str(exit_code)}
    )


if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="0.0.0.0", port=8080)
