---
title: "FIX: Cannot connect to the Docker daemon at unix:///var/run/docker.sock"
description: "Solve the 'Cannot connect to the Docker daemon' error in seconds. Learn whether it's a service issue or a permissions problem, and fix it permanently."
date: 2026-02-11
tags: ["docker", "debug", "linux", "devops"]
keywords: ["cannot connect to the docker daemon", "docker daemon not running", "docker.sock permission denied", "var run docker.sock", "is the docker daemon running", "docker service start", "docker permission denied", "docker socket error", "sudo docker fix", "docker usermod group"]
draft: false
schema_json: >
  {
    "@context": "https://schema.org",
    "@type": "TechArticle",
    "name": "FIX: Cannot connect to the Docker daemon at unix:///var/run/docker.sock",
    "description": "Step-by-step fix for the Docker daemon connection error on Linux.",
    "proficiencyLevel": "Beginner",
    "inLanguage": "en"
  }
---

## The Error

You run a Docker command and get hit with this:

```
Cannot connect to the Docker daemon at unix:///var/run/docker.sock. Is the docker daemon running?
```

Or a variation:

```
Got permission denied while trying to connect to the Docker daemon socket at unix:///var/run/docker.sock
```

This is one of the most common Docker errors on Linux. It means your shell cannot communicate with the Docker engine. The cause is always one of two things: the Docker service is not running, or your user does not have permission to access the Docker socket.

---

## The Quick Fix

### 1. Start the Docker service

The daemon might simply not be running. Start it:

```bash
# Start Docker now
sudo systemctl start docker

# Enable Docker to start on boot
sudo systemctl enable docker

# Verify it's running
sudo systemctl status docker
```

If `status` shows `active (running)`, the service is up. Try your Docker command again.

### 2. Fix user permissions

If the service is running but you still get "permission denied", your user is not in the `docker` group:

```bash
# Add your user to the docker group
sudo usermod -aG docker $USER

# Apply the new group membership (or log out and back in)
newgrp docker

# Verify you're in the group
groups
```

After this, you should be able to run `docker ps` without `sudo`.

---

## The Explanation

Docker uses a Unix socket (`/var/run/docker.sock`) to communicate between the CLI client and the Docker daemon (the background service). Two things must be true for this to work:

**1. The Docker daemon must be running.** The systemd service `docker.service` manages the daemon. If the machine was just booted and Docker is not enabled on startup, or if the service crashed, the socket file either does not exist or is not accepting connections.

**2. Your user must have access to the socket.** By default, the Docker socket is owned by `root:docker` with permissions `srw-rw----`. This means only root and members of the `docker` group can read/write to it. If your user is not in the `docker` group, every command requires `sudo`.

### Which one is it?

```bash
# Check if the service is running
systemctl is-active docker

# Check socket permissions
ls -la /var/run/docker.sock

# Check if your user is in the docker group
groups $USER
```

If `systemctl is-active` returns `inactive` → it is a **service issue** (Fix #1).
If the service is `active` but you get permission denied → it is a **permissions issue** (Fix #2).

---

## Common Pitfalls

- **Snap-installed Docker**: If you installed Docker via Snap instead of the official repo, the socket path and service name may differ. Uninstall the Snap version and use the official Docker CE packages.
- **WSL2 on Windows**: The Docker daemon does not run natively in WSL2. You need Docker Desktop for Windows running, or you must install and start the daemon inside your WSL2 distro manually.
- **Docker Desktop on Mac/Linux**: If you are using Docker Desktop, the daemon is managed by the Desktop app, not systemd. Make sure Docker Desktop is open and running.

---

## Related Resources

Prevent this error from happening again. Bookmark our complete [Docker Captain's Log Cheatsheet](/cheatsheets/docker-container-commands/) — it covers user permissions, service management, and every `docker` command you need in production.

Need to manage Linux services and users? See the [Linux SysAdmin: Permissions & Process Management Cheatsheet](/cheatsheets/linux-sysadmin-permissions/).
