# yolo-cage Development Context

## What This Is

yolo-cage is a product for public release on Show HN. It lets developers run Claude Code in a sandboxed VM with git branch isolation.

## The Product

The user runs `vagrant up` and gets a working yolo-cage VM. That's it. No bespoke setup, no "works on my machine," no special infrastructure.

## Current Task

Build and test the deterministic VM build:
1. `vagrant up` provisions a fresh Ubuntu VM
2. `build-release.sh` installs everything
3. User runs `yolo-cage-configure` with their credentials
4. User runs `yolo-cage create <branch>` to start working

## What NOT To Do

- Do NOT suggest testing on ark or any existing infrastructure
- Do NOT add flags or options for "flexibility"
- Do NOT try to support arbitrary Kubernetes clusters
- Do NOT shortcut the VM testing - the VM IS the product

## CI Requirements

**The main branch must always build successfully in CI.**

Before merging any PR:
1. `vagrant up` must complete without errors
2. The resulting VM must be ready for `yolo-cage-configure`

WIP branches can be broken, but nothing gets merged to main unless CI passes.

## Environment

- Development machine: ark (Ubuntu server, headless)
- Vagrant provider: libvirt/KVM (NOT VirtualBox - this is a server)
- Target: Fresh Ubuntu 22.04 VM

## Testing

After `vagrant up` completes, test with:
```bash
vagrant ssh
yolo-cage-configure --init
# Edit ~/.yolo-cage/config.yaml with your credentials
yolo-cage-configure
yolo-cage create test-branch
yolo-cage list
yolo-cage delete test-branch
```
