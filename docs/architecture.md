# Architecture

This document explains how yolo-cage works and the security model it implements.

## The Problem

You want AI coding agents working autonomously on your codebase without babysitting permission prompts. But YOLO mode (`--dangerously-skip-permissions`) feels irresponsible because agents have what Simon Willison calls the ["lethal trifecta"](https://simonwillison.net/2025/Jun/16/the-lethal-trifecta/):

1. **Internet access** - for docs, APIs, package registries
2. **Code execution** - that's the whole point
3. **Secrets** - API keys, credentials in environment

Any two are manageable. All three together means the agent can read your secrets and send them anywhere.

## The Solution

yolo-cage runs Claude Code inside a VM with a single-node Kubernetes cluster. The agent can do whatever it wants inside its container, but all external communication is intercepted and controlled:

- **Git operations** go through a dispatcher that enforces branch isolation
- **HTTP/HTTPS traffic** goes through a proxy that scans for secrets
- **Network policy** restricts what the container can reach

The container boundary is the sandbox. The dispatcher and proxy are the controls.

## System Overview

```
┌─────────────────────────────────────────────────────────────────────┐
│ Host Machine                                                         │
│                                                                     │
│   ~/.yolo-cage/config.env     yolo-cage CLI                        │
│                                    │                                │
└────────────────────────────────────┼────────────────────────────────┘
                                     │ vagrant ssh
                                     ▼
┌─────────────────────────────────────────────────────────────────────┐
│ Vagrant VM (Ubuntu + MicroK8s)                                       │
│                                                                     │
│  ┌──────────────────────────────────────────────────────────────┐   │
│  │ Kubernetes Cluster                                            │   │
│  │                                                              │   │
│  │  ┌─────────────┐  ┌─────────────┐  ┌─────────────┐          │   │
│  │  │ yolo-cage   │  │ yolo-cage   │  │ yolo-cage   │          │   │
│  │  │ (feature-a) │  │ (feature-b) │  │ (bugfix-c)  │          │   │
│  │  │             │  │             │  │             │          │   │
│  │  │ Claude Code │  │ Claude Code │  │ Claude Code │          │   │
│  │  │ in YOLO mode│  │ in YOLO mode│  │ in YOLO mode│          │   │
│  │  └──────┬──────┘  └──────┬──────┘  └──────┬──────┘          │   │
│  │         │                │                │                  │   │
│  │         └───────────┬────┴────────────────┘                  │   │
│  │                     │                                        │   │
│  │         ┌───────────┴───────────┐                           │   │
│  │         ▼                       ▼                           │   │
│  │  ┌─────────────┐         ┌─────────────┐                    │   │
│  │  │ Git         │         │ Egress      │                    │   │
│  │  │ Dispatcher  │         │ Proxy       │                    │   │
│  │  │             │         │ (mitmproxy) │                    │   │
│  │  │ • Branch    │         │             │                    │   │
│  │  │   enforce   │         │ • Secret    │                    │   │
│  │  │ • Pre-push  │         │   scanning  │                    │   │
│  │  │   hooks     │         │ • Domain    │                    │   │
│  │  └──────┬──────┘         │   blocking  │                    │   │
│  │         │                └──────┬──────┘                    │   │
│  │         │                       │                           │   │
│  └─────────┼───────────────────────┼───────────────────────────┘   │
│            │                       │                               │
└────────────┼───────────────────────┼───────────────────────────────┘
             │                       │
             ▼                       ▼
         GitHub                  Internet
         (HTTPS)                 (filtered)
```

## Components

### Host CLI (`yolo-cage`)

The command-line interface that runs on your machine. It manages the VM lifecycle and delegates pod operations to the VM:

- `yolo-cage build` - Clone repo, configure, create VM
- `yolo-cage up/down` - Start/stop VM
- `yolo-cage create/attach/delete` - Manage sandbox pods

### Vagrant VM

An Ubuntu 22.04 VM running MicroK8s (single-node Kubernetes). The VM provides:

- Isolation from your host system
- A Kubernetes environment for running pods
- Network control via Kubernetes NetworkPolicy

### Sandbox Pods

Each agent runs in its own Kubernetes pod with:

- **Claude Code** in YOLO mode (no permission prompts)
- **tmux** for session persistence across disconnects
- **Git/gh shims** that intercept commands and route them to the dispatcher
- **Proxy environment variables** that route HTTP/HTTPS through the egress proxy

Pods run as a non-root user (UID 1000) with no host filesystem access.

### Git Dispatcher

A FastAPI service that intercepts all git and GitHub CLI operations:

**Git command classification:**
- `LOCAL` - No restrictions: add, commit, status, log, diff, etc.
- `BRANCH` - Allowed with warnings: checkout, switch, branch
- `MERGE` - Only on assigned branch: merge, rebase, cherry-pick
- `REMOTE_READ` - Allowed: fetch, pull
- `REMOTE_WRITE` - Enforced: push (only to assigned branch)
- `DENIED` - Blocked: remote, clone, config, credential, submodule

**Branch enforcement:**
- Each pod is assigned a branch at creation
- Agents can only push to their assigned branch
- Push refspecs like `HEAD:main` are blocked
- Pushing to URLs (vs remote names) is blocked

**Pre-push hooks:**
- TruffleHog runs before every push
- Scans commits for secrets
- Blocks push if secrets detected

**GitHub CLI controls:**
- `gh pr create/view/comment` - Allowed
- `gh pr merge` - Blocked
- `gh repo delete/create` - Blocked
- `gh api` - Blocked (would bypass controls)

### Egress Proxy

An mitmproxy instance that intercepts all HTTP/HTTPS traffic:

**Secret scanning:**
- Scans request bodies, headers, URL paths, and query parameters
- Uses LLM-Guard for pattern detection
- Blocks requests containing credential patterns
- **Fails closed** - if scanner is unavailable, requests are blocked

**Domain blocking:**
- Blocks known exfiltration sites (pastebin, file.io, etc.)

**GitHub API restrictions:**
- Blocks `PUT /repos/*/pulls/*/merge` (PR merge)
- Blocks `DELETE /repos/*` (repo deletion)
- Blocks webhook and branch protection modifications

### Network Policy

Kubernetes NetworkPolicy restricts pod network access:

- **Allowed:** DNS (53), dispatcher (8080), proxy (8080), direct HTTPS (443)
- **Blocked:** SSH (22), all other ports

The only way out is through the dispatcher (for git) or the proxy (for HTTP/HTTPS).

## Security Properties

### What agents CAN do

- Read the entire repository (all branches)
- Commit and push to their assigned branch
- Open pull requests
- Comment on issues and PRs
- Install packages, run tests, execute code
- Access the internet (through proxy)

### What agents CANNOT do

- Push to any branch other than their assigned one
- Merge pull requests
- Delete repositories or branches
- Exfiltrate secrets through HTTP/HTTPS
- Bypass the dispatcher for git operations
- Access GitHub API directly (blocked at proxy)

### Defense in Depth

Multiple layers must fail for an escape:

1. **Git shim** - Must be bypassed to reach real git
2. **Dispatcher** - Must allow the operation
3. **Pre-push hooks** - Must not detect secrets
4. **Egress proxy** - Must not detect secrets in HTTP
5. **Network policy** - Must allow the traffic

## Known Limitations

### Not Fully Mitigated

- **DNS exfiltration** - Data could be encoded in DNS queries
- **Timing side channels** - Information could leak via response timing
- **Steganography** - Secrets could hide in images or binary data

### Residual Risk

This setup reduces risk; it does not eliminate it. Do not use for:

- Production secrets
- Credentials with broad access
- Anything where exfiltration would be catastrophic

Use scoped credentials and treat the sandbox as defense-in-depth, not a fortress.

## File Locations

| Component | Location |
|-----------|----------|
| Host CLI | `scripts/yolo-cage` |
| VM CLI | `scripts/yolo-cage-inner` |
| Git dispatcher | `dispatcher/` |
| Egress proxy | `proxy/` |
| Kubernetes manifests | `manifests/` |
| Container images | `dockerfiles/` |
