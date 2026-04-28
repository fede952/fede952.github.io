---
title: "Docker 面试题 Top 20 及答案（2026 年版）"
description: "通过这 20 个涵盖容器、镜像、网络、卷、Docker Compose 和生产最佳实践的高级 Docker 面试题，助你顺利通过高级 DevOps 面试。"
date: 2026-02-11
tags: ["docker", "interview", "devops", "containers"]
keywords: ["docker面试题", "高级devops面试", "容器化问题", "docker面试答案", "docker compose面试", "dockerfile最佳实践", "容器编排面试", "docker网络问题", "devops工程师面试", "docker生产问题"]
draft: false
schema_json: >
  {
    "@context": "https://schema.org",
    "@type": "TechArticle",
    "name": "Docker 面试题 Top 20 及答案（2026 年版）",
    "description": "面向高级 DevOps 岗位的高级 Docker 面试题，涵盖容器、镜像、网络和生产最佳实践。",
    "proficiencyLevel": "Advanced",
    "inLanguage": "zh-CN"
  }
---

## 系统初始化

Docker 已成为所有 DevOps、SRE 或后端工程岗位的必备技能。高级面试官期望你不仅仅停留在 `docker run` — 他们希望看到你理解镜像分层、网络内部机制、安全加固和生产级编排模式。本指南包含高级和主管级面试中最常被问到的 20 个问题，以及展示深度的详细答案。

**面试前需要快速回顾命令？** 收藏我们的 [Docker Captain's Log 速查表](/cheatsheets/docker-container-commands/)。

---

## 核心概念

<details>
<summary><strong>1. 容器和虚拟机有什么区别？</strong></summary>
<br>

**虚拟机**在虚拟机管理程序上运行完整的客户操作系统，包括自己的内核、驱动程序和系统库。每个虚拟机完全隔离，但消耗大量资源（数 GB 内存，启动需要数分钟）。

**容器**共享宿主操作系统内核，使用 Linux 命名空间和 cgroups 隔离进程。它只打包应用程序及其依赖项 — 无需单独的内核。这使容器轻量（MB 级别）、启动快速（毫秒级）且高度可移植。

关键区别：虚拟机虚拟化**硬件**，容器虚拟化**操作系统**。
</details>

<details>
<summary><strong>2. Docker 镜像层是什么？它们如何工作？</strong></summary>
<br>

Docker 镜像由一系列**只读层**构建。Dockerfile 中的每条指令（`FROM`、`RUN`、`COPY` 等）都会创建一个新层。这些层使用联合文件系统（如 OverlayFS）堆叠在一起。

当容器运行时，Docker 在顶部添加一个薄的**可写层**（容器层）。运行时所做的更改只影响这个可写层 — 底层的镜像层保持不变。

这种架构实现了：
- **缓存**：如果某一层没有变化，Docker 在构建时从缓存中重用它。
- **共享**：来自同一镜像的多个容器共享只读层，节省磁盘空间。
- **效率**：只有修改过的层需要从注册表拉取或推送。
</details>

<details>
<summary><strong>3. Dockerfile 中 CMD 和 ENTRYPOINT 有什么区别？</strong></summary>
<br>

两者都定义容器启动时运行什么，但行为不同：

- **CMD** 提供可以在运行时完全覆盖的默认参数。如果运行 `docker run myimage /bin/bash`，CMD 会被替换。
- **ENTRYPOINT** 定义始终运行的主可执行文件。运行时参数会追加到它后面，而不是替换它。

最佳实践：将 `ENTRYPOINT` 用于主进程，将 `CMD` 用于默认参数：

```dockerfile
ENTRYPOINT ["python", "app.py"]
CMD ["--port", "8080"]
```

运行 `docker run myimage --port 3000` 将执行 `python app.py --port 3000`。
</details>

<details>
<summary><strong>4. 什么是多阶段构建？为什么它很重要？</strong></summary>
<br>

多阶段构建在单个 Dockerfile 中使用多个 `FROM` 语句。每个 `FROM` 开始一个新的构建阶段，你可以选择性地将产物从一个阶段复制到另一个阶段。

```dockerfile
# Stage 1: Build
FROM golang:1.21 AS builder
WORKDIR /app
COPY . .
RUN go build -o myapp

# Stage 2: Run (minimal image)
FROM alpine:3.18
COPY --from=builder /app/myapp /usr/local/bin/
CMD ["myapp"]
```

这会生成一个只包含编译后二进制文件的最终镜像 — 没有构建工具、没有源代码、没有中间文件。结果是一个大幅缩小的镜像（通常小 10-100 倍），攻击面也随之减少。
</details>

<details>
<summary><strong>5. Dockerfile 中 COPY 和 ADD 有什么区别？</strong></summary>
<br>

两者都从构建上下文复制文件到镜像中，但 `ADD` 有额外功能：
- `ADD` 可以自动解压本地 `.tar` 归档文件。
- `ADD` 可以从 URL 下载文件。

然而，Docker 最佳实践建议在几乎所有情况下使用 `COPY`，因为它明确且可预测。仅在特别需要 tar 解压时使用 `ADD`。不要使用 `ADD` 下载文件 — 改用 `RUN curl` 或 `RUN wget`，这样下载层可以被正确缓存。
</details>

## 网络

<details>
<summary><strong>6. 解释 Docker 的网络模式（bridge、host、none、overlay）。</strong></summary>
<br>

- **Bridge**（默认）：在宿主机上创建私有内部网络。同一 bridge 上的容器可以通过 IP 或容器名称通信。外部流量需要端口映射（`-p`）。
- **Host**：移除网络隔离。容器直接共享宿主机的网络栈。不需要端口映射，但也没有隔离。适用于对性能要求极高的应用。
- **None**：完全没有网络。容器只有回环接口。用于批处理任务或安全敏感的工作负载。
- **Overlay**：跨越多个 Docker 主机（用于 Swarm/Kubernetes）。不同机器上的容器可以使用 VXLAN 隧道像在同一网络上一样通信。
</details>

<details>
<summary><strong>7. 容器间通信如何工作？</strong></summary>
<br>

在用户自定义的 bridge 网络上，容器可以通过 Docker 内置的 DNS 解析器**以容器名称**互相访问。DNS 服务器在每个容器内部的 `127.0.0.11` 上运行。

在默认的 bridge 网络上，DNS 解析**不可用** — 容器只能通过 IP 地址通信，由于 IP 是动态分配的，这是不可靠的。

最佳实践：始终创建自定义 bridge 网络（`docker network create mynet`）并将容器连接到它。不要依赖默认 bridge 进行容器间通信。
</details>

<details>
<summary><strong>8. EXPOSE 和发布端口有什么区别？</strong></summary>
<br>

Dockerfile 中的 `EXPOSE` 纯粹是**文档** — 它告诉读者应用程序在特定端口上监听。它实际上不会打开或映射端口。

发布端口（`-p 8080:80`）实际上会创建一个网络规则，将宿主机端口映射到容器端口，使服务可以从容器外部访问。

你可以发布不在 `EXPOSE` 指令中的端口，而且 `EXPOSE` 本身没有 `-p` 不会做任何事情。
</details>

## 卷和存储

<details>
<summary><strong>9. Docker 的三种挂载类型是什么？</strong></summary>
<br>

1. **卷**（`docker volume create`）：由 Docker 管理，存储在 `/var/lib/docker/volumes/`。最适合持久化数据（数据库）。容器删除后依然保留。可在主机间移植。
2. **绑定挂载**（`-v /host/path:/container/path`）：将特定的宿主机目录映射到容器中。宿主机路径必须存在。最适合开发（实时代码重载）。不可移植。
3. **tmpfs 挂载**（`--tmpfs /tmp`）：仅存储在宿主机内存中。永远不会写入磁盘。最适合不应持久化的敏感数据（密钥、会话令牌）。
</details>

<details>
<summary><strong>10. 如何持久化数据库容器的数据？</strong></summary>
<br>

使用挂载到数据库数据目录的**命名卷**：

```bash
docker volume create pgdata
docker run -d -v pgdata:/var/lib/postgresql/data postgres:16
```

数据在容器重启和删除后依然保留。升级数据库版本时，停止旧容器，用相同的卷启动新容器，让新版本处理数据迁移。

不要在生产数据库中使用绑定挂载 — 卷具有更好的 I/O 性能，并由 Docker 的存储驱动程序管理。
</details>

## 安全

<details>
<summary><strong>11. 如何在生产环境中保护 Docker 容器？</strong></summary>
<br>

关键加固实践：
- **以非 root 用户运行**：在 Dockerfile 中使用 `USER` 指令。永远不要以 root 身份运行应用进程。
- **使用最小基础镜像**：使用 `alpine`、`distroless` 或 `scratch` 代替 `ubuntu`。
- **删除 capability**：使用 `--cap-drop ALL --cap-add <仅需要的>`。
- **只读文件系统**：使用 `--read-only`，仅挂载特定的可写路径。
- **禁止新权限**：使用 `--security-opt=no-new-privileges`。
- **扫描镜像**：使用 `docker scout`、Trivy 或 Snyk 检测基础镜像和依赖中的漏洞。
- **签名镜像**：使用 Docker Content Trust（`DOCKER_CONTENT_TRUST=1`）验证镜像真实性。
- **限制资源**：使用 `--memory`、`--cpus` 防止资源耗尽。
</details>

<details>
<summary><strong>12. Docker rootless 模式是什么？</strong></summary>
<br>

Docker rootless 模式在用户命名空间内完全运行 Docker 守护进程和容器，无需宿主机上的 root 权限。这消除了 Docker 的主要安全顾虑：守护进程以 root 身份运行，容器逃逸意味着获得宿主机的 root 访问权限。

在 rootless 模式下，即使攻击者逃离容器，也只能获得运行 Docker 的非特权用户的权限。权衡是某些功能（如绑定 1024 以下的端口）需要额外配置。
</details>

## Docker Compose 和编排

<details>
<summary><strong>13. docker-compose up 和 docker-compose run 有什么区别？</strong></summary>
<br>

- `docker compose up`：启动 `docker-compose.yml` 中定义的**所有**服务，创建网络/卷，并遵守 `depends_on` 顺序。通常用于启动整个技术栈。
- `docker compose run <服务> <命令>`：使用一次性命令启动**单个**服务。默认不启动依赖服务（使用 `--service-ports` 映射端口，`--rm` 清理）。用于运行迁移、测试或管理任务。
</details>

<details>
<summary><strong>14. depends_on 如何工作？它有什么限制？</strong></summary>
<br>

`depends_on` 控制**启动顺序** — 确保服务 A 在服务 B 之前启动。但是，它只等待容器**启动**，而不是等待内部应用程序**就绪**。

例如，数据库容器可能在几秒内启动，但 PostgreSQL 需要额外时间进行初始化。你的应用容器会启动并立即连接失败。

解决方案：将 `depends_on` 与 `condition` 和健康检查一起使用：

```yaml
services:
  db:
    image: postgres:16
    healthcheck:
      test: ["CMD-SHELL", "pg_isready -U user"]
      interval: 5s
      timeout: 5s
      retries: 5
  app:
    depends_on:
      db:
        condition: service_healthy
```
</details>

<details>
<summary><strong>15. 什么时候选择 Docker Swarm 而不是 Kubernetes？</strong></summary>
<br>

**Docker Swarm**：内置于 Docker，无需额外设置。最适合简单性至关重要的中小型部署。使用相同的 Docker Compose 文件。与 Kubernetes 相比，生态系统和社区有限。适合没有专职平台工程师的团队。

**Kubernetes**：大规模容器编排的行业标准。支持自动扩缩容、滚动更新、服务网格、自定义资源定义和庞大的生态系统（Helm、Istio、ArgoCD）。复杂度和学习曲线更高。大规模、多团队、多云部署所必需。

经验法则：如果你有少于 20 个服务和小团队，Swarm 就足够了。超过这个规模，Kubernetes 值得投资。
</details>

## 生产环境和故障排除

<details>
<summary><strong>16. 如何减小 Docker 镜像大小？</strong></summary>
<br>

1. **使用多阶段构建** — 将构建工具排除在最终镜像之外。
2. **使用最小基础镜像** — 使用 `alpine`（约 5MB）代替 `ubuntu`（约 75MB）。
3. **合并 RUN 命令** — 每个 `RUN` 创建一个层。用 `&&` 链接命令并在同一层中清理。
4. **使用 .dockerignore** — 从构建上下文中排除 `node_modules`、`.git`、测试文件、文档。
5. **按变更频率排列层** — 将很少变更的层（依赖）放在经常变更的层（源代码）之前，以最大化缓存命中率。
</details>

<details>
<summary><strong>17. 容器持续重启。如何调试？</strong></summary>
<br>

逐步排查方法：
1. `docker ps -a` — 检查退出码。退出码 137 = OOM 终止。退出码 1 = 应用错误。
2. `docker logs <container>` — 查看应用日志中的堆栈跟踪或错误信息。
3. `docker inspect <container>` — 检查 `State.OOMKilled`、资源限制和环境变量。
4. `docker run -it --entrypoint /bin/sh <image>` — 启动交互式 shell 手动调试环境。
5. `docker stats` — 检查容器是否达到内存或 CPU 限制。
6. 检查 `docker events` — 查找守护进程的 kill 信号或 OOM 事件。
</details>

<details>
<summary><strong>18. docker stop 和 docker kill 有什么区别？</strong></summary>
<br>

- `docker stop` 向主进程（PID 1）发送 **SIGTERM**，并等待宽限期（默认 10 秒）。如果进程没有退出，Docker 发送 SIGKILL。这允许应用程序执行优雅关闭（关闭连接、刷新缓冲区、保存状态）。
- `docker kill` 立即发送 **SIGKILL**。进程在没有任何清理机会的情况下被终止。仅在容器无响应时使用。

最佳实践：在生产环境中始终使用 `docker stop`。确保你的应用程序正确处理 SIGTERM。
</details>

<details>
<summary><strong>19. 如何在 Docker 中处理密钥？</strong></summary>
<br>

**永远不要**将密钥嵌入镜像中（Dockerfile 中的 ENV、COPY .env 文件）。它们会持久化在镜像层中，通过 `docker history` 可见。

按成熟度级别的方法：
- **基本**：在运行时通过 `--env-file` 传递密钥（文件不包含在镜像中）。
- **更好**：使用 Docker Swarm secrets 或 Kubernetes secrets（以文件形式挂载，而非环境变量）。
- **最佳**：使用外部密钥管理器（HashiCorp Vault、AWS Secrets Manager、Azure Key Vault），并在运行时通过 sidecar 或 init container 注入密钥。
</details>

<details>
<summary><strong>20. Docker 健康检查是什么？为什么它至关重要？</strong></summary>
<br>

健康检查是 Docker 在容器内部定期执行的命令，用于验证应用程序是否真正在工作 — 而不仅仅是进程在运行。

```dockerfile
HEALTHCHECK --interval=30s --timeout=5s --retries=3 \
  CMD curl -f http://localhost:3000/health || exit 1
```

没有健康检查，Docker 只知道进程是否存活（PID 存在）。有了健康检查，Docker 知道应用程序是否**健康**（响应请求）。这对以下方面至关重要：
- **负载均衡器**：仅将流量路由到健康的容器。
- **编排器**：自动重启不健康的容器。
- **depends_on**：等待实际就绪，而不仅仅是进程启动。
</details>
