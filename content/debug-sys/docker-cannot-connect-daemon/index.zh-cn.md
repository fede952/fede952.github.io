---
title: "修复: Cannot connect to the Docker daemon at unix:///var/run/docker.sock"
description: "几秒钟内解决 'Cannot connect to the Docker daemon' 错误。了解是服务问题还是权限问题，并永久修复它。"
date: 2026-02-11
tags: ["docker", "debug", "linux", "devops"]
keywords: ["cannot connect to the docker daemon", "docker daemon not running", "docker.sock permission denied", "var run docker.sock", "is the docker daemon running", "docker service start", "docker permission denied", "docker socket error", "sudo docker fix", "docker usermod group"]
draft: false
schema_json: >
  {
    "@context": "https://schema.org",
    "@type": "TechArticle",
    "name": "修复: Cannot connect to the Docker daemon at unix:///var/run/docker.sock",
    "description": "Linux 上 Docker 守护进程连接错误的分步修复指南。",
    "proficiencyLevel": "Beginner",
    "inLanguage": "zh-CN"
  }
---

## 错误信息

你运行 Docker 命令时遇到了这个错误：

```
Cannot connect to the Docker daemon at unix:///var/run/docker.sock. Is the docker daemon running?
```

或者一个变体：

```
Got permission denied while trying to connect to the Docker daemon socket at unix:///var/run/docker.sock
```

这是 Linux 上最常见的 Docker 错误之一。它意味着你的 shell 无法与 Docker 引擎通信。原因总是以下两种之一：Docker 服务未运行，或者你的用户没有访问 Docker 套接字的权限。

---

## 快速修复

### 1. 启动 Docker 服务

守护进程可能只是没有运行。启动它：

```bash
# Start Docker now
sudo systemctl start docker

# Enable Docker to start on boot
sudo systemctl enable docker

# Verify it's running
sudo systemctl status docker
```

如果 `status` 显示 `active (running)`，服务已启动。再次尝试你的 Docker 命令。

### 2. 修复用户权限

如果服务正在运行但你仍然收到 "permission denied"，说明你的用户不在 `docker` 组中：

```bash
# Add your user to the docker group
sudo usermod -aG docker $USER

# Apply the new group membership (or log out and back in)
newgrp docker

# Verify you're in the group
groups
```

完成后，你应该能够在不使用 `sudo` 的情况下运行 `docker ps`。

---

## 详细说明

Docker 使用 Unix 套接字（`/var/run/docker.sock`）在 CLI 客户端和 Docker 守护进程（后台服务）之间进行通信。要使其正常工作，必须满足两个条件：

**1. Docker 守护进程必须正在运行。** systemd 服务 `docker.service` 管理守护进程。如果机器刚刚启动且 Docker 未设置为开机启动，或者服务崩溃了，套接字文件要么不存在，要么不接受连接。

**2. 你的用户必须有权访问套接字。** 默认情况下，Docker 套接字的所有者是 `root:docker`，权限为 `srw-rw----`。这意味着只有 root 和 `docker` 组的成员才能对其进行读写。如果你的用户不在 `docker` 组中，每个命令都需要 `sudo`。

### 如何判断是哪个问题？

```bash
# Check if the service is running
systemctl is-active docker

# Check socket permissions
ls -la /var/run/docker.sock

# Check if your user is in the docker group
groups $USER
```

如果 `systemctl is-active` 返回 `inactive` → 这是**服务问题**（修复 #1）。
如果服务是 `active` 但你收到 permission denied → 这是**权限问题**（修复 #2）。

---

## 常见陷阱

- **通过 Snap 安装的 Docker**：如果你通过 Snap 而不是官方仓库安装了 Docker，套接字路径和服务名称可能不同。卸载 Snap 版本并使用官方 Docker CE 软件包。
- **Windows 上的 WSL2**：Docker 守护进程不能在 WSL2 中原生运行。你需要运行 Docker Desktop for Windows，或者必须在 WSL2 发行版中手动安装并启动守护进程。
- **Mac/Linux 上的 Docker Desktop**：如果你使用的是 Docker Desktop，守护进程由 Desktop 应用管理，而不是 systemd。确保 Docker Desktop 已打开并正在运行。

---

## 相关资源

防止此错误再次发生。收藏我们完整的 [Docker Captain's Log Cheatsheet](/cheatsheets/docker-container-commands/) — 涵盖用户权限、服务管理以及生产环境中所需的所有 `docker` 命令。

需要管理 Linux 服务和用户？请参阅 [Linux SysAdmin: Permissions & Process Management Cheatsheet](/cheatsheets/linux-sysadmin-permissions/)。
