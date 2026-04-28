---
title: "Top 20 Docker Interview Questions & Answers (2026 Edition)"
description: "Ace your Senior DevOps interview with these 20 advanced Docker questions covering containers, images, networking, volumes, Docker Compose, and production best practices."
date: 2026-02-11
tags: ["docker", "interview", "devops", "containers"]
keywords: ["docker interview questions", "senior devops interview", "containerization questions", "docker interview answers", "docker compose interview", "dockerfile best practices", "container orchestration interview", "docker networking questions", "devops engineer interview", "docker production questions"]
draft: false
schema_json: >
  {
    "@context": "https://schema.org",
    "@type": "TechArticle",
    "name": "Top 20 Docker Interview Questions & Answers (2026 Edition)",
    "description": "Advanced Docker interview questions for Senior DevOps roles covering containers, images, networking, and production best practices.",
    "proficiencyLevel": "Advanced",
    "inLanguage": "en"
  }
---

## System Init

Docker has become a non-negotiable skill for any DevOps, SRE, or backend engineering role. Interviewers at senior level expect you to go beyond `docker run` — they want to see that you understand image layering, networking internals, security hardening, and production-grade orchestration patterns. This guide contains the 20 questions most frequently asked in Senior and Lead-level interviews, with detailed answers that demonstrate depth.

**Need a quick command refresher before your interview?** Bookmark our [Docker Captain's Log Cheatsheet](/cheatsheets/docker-container-commands/).

---

## Core Concepts

<details>
<summary><strong>1. What is the difference between a container and a virtual machine?</strong></summary>
<br>

A **virtual machine** runs a full guest OS on top of a hypervisor, including its own kernel, drivers, and system libraries. Each VM is completely isolated but consumes significant resources (GBs of RAM, minutes to boot).

A **container** shares the host OS kernel and isolates processes using Linux namespaces and cgroups. It packages only the application and its dependencies — no separate kernel. This makes containers lightweight (MBs), fast to start (milliseconds), and highly portable.

Key difference: VMs virtualize **hardware**, containers virtualize the **operating system**.
</details>

<details>
<summary><strong>2. What are Docker image layers and how do they work?</strong></summary>
<br>

A Docker image is built from a series of **read-only layers**. Each instruction in a Dockerfile (`FROM`, `RUN`, `COPY`, etc.) creates a new layer. Layers are stacked on top of each other using a union filesystem (like OverlayFS).

When a container runs, Docker adds a thin **writable layer** on top (the container layer). Changes made at runtime only affect this writable layer — the underlying image layers remain unchanged.

This architecture enables:
- **Caching**: If a layer hasn't changed, Docker reuses it from cache during builds.
- **Sharing**: Multiple containers from the same image share the read-only layers, saving disk space.
- **Efficiency**: Only modified layers need to be pulled or pushed to registries.
</details>

<details>
<summary><strong>3. What is the difference between CMD and ENTRYPOINT in a Dockerfile?</strong></summary>
<br>

Both define what runs when a container starts, but they behave differently:

- **CMD** provides default arguments that can be completely overridden at runtime. If you run `docker run myimage /bin/bash`, the CMD is replaced.
- **ENTRYPOINT** defines the main executable that always runs. Runtime arguments are appended to it, not replaced.

Best practice: Use `ENTRYPOINT` for the main process and `CMD` for default arguments:

```dockerfile
ENTRYPOINT ["python", "app.py"]
CMD ["--port", "8080"]
```

Running `docker run myimage --port 3000` will execute `python app.py --port 3000`.
</details>

<details>
<summary><strong>4. What is a multi-stage build and why is it important?</strong></summary>
<br>

A multi-stage build uses multiple `FROM` statements in a single Dockerfile. Each `FROM` starts a new build stage, and you can selectively copy artifacts from one stage to another.

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

This produces a final image containing only the compiled binary — no build tools, no source code, no intermediate files. The result is a dramatically smaller image (often 10-100x smaller) with a reduced attack surface.
</details>

<details>
<summary><strong>5. What is the difference between COPY and ADD in a Dockerfile?</strong></summary>
<br>

Both copy files from the build context into the image, but `ADD` has extra features:
- `ADD` can extract local `.tar` archives automatically.
- `ADD` can download files from URLs.

However, Docker best practices recommend using `COPY` in almost all cases because it is explicit and predictable. Use `ADD` only when you specifically need tar extraction. Never use `ADD` for downloading files — use `RUN curl` or `RUN wget` instead, so the download layer can be cached properly.
</details>

## Networking

<details>
<summary><strong>6. Explain Docker's networking modes (bridge, host, none, overlay).</strong></summary>
<br>

- **Bridge** (default): Creates a private internal network on the host. Containers on the same bridge can communicate by IP or container name. Traffic to the outside requires port mapping (`-p`).
- **Host**: Removes network isolation. The container shares the host's network stack directly. No port mapping needed, but no isolation either. Useful for performance-critical applications.
- **None**: No networking at all. The container has only a loopback interface. Used for batch jobs or security-sensitive workloads.
- **Overlay**: Spans multiple Docker hosts (used in Swarm/Kubernetes). Containers on different machines can communicate as if on the same network, using VXLAN tunneling.
</details>

<details>
<summary><strong>7. How does container-to-container communication work?</strong></summary>
<br>

On a user-defined bridge network, containers can reach each other **by container name** via Docker's built-in DNS resolver. The DNS server runs at `127.0.0.11` inside every container.

On the default bridge network, DNS resolution is **not** available — containers can only communicate by IP address, which is unreliable since IPs are assigned dynamically.

Best practice: Always create a custom bridge network (`docker network create mynet`) and attach containers to it. Never rely on the default bridge for inter-container communication.
</details>

<details>
<summary><strong>8. What is the difference between EXPOSE and publishing a port?</strong></summary>
<br>

`EXPOSE` in a Dockerfile is purely **documentation** — it tells anyone reading the Dockerfile that the application listens on a specific port. It does NOT actually open or map the port.

Publishing a port (`-p 8080:80`) actually creates a network rule that maps a host port to a container port, making the service accessible from outside the container.

You can publish ports that are not in the `EXPOSE` directive, and `EXPOSE` alone does nothing without `-p`.
</details>

## Volumes & Storage

<details>
<summary><strong>9. What are the three types of Docker mounts?</strong></summary>
<br>

1. **Volumes** (`docker volume create`): Managed by Docker, stored in `/var/lib/docker/volumes/`. Best for persistent data (databases). Survives container removal. Portable between hosts.
2. **Bind mounts** (`-v /host/path:/container/path`): Maps a specific host directory into the container. The host path must exist. Best for development (live code reloading). Not portable.
3. **tmpfs mounts** (`--tmpfs /tmp`): Stored in the host's memory only. Never written to disk. Best for sensitive data that should not persist (secrets, session tokens).
</details>

<details>
<summary><strong>10. How do you persist data from a database container?</strong></summary>
<br>

Use a **named volume** mounted to the database's data directory:

```bash
docker volume create pgdata
docker run -d -v pgdata:/var/lib/postgresql/data postgres:16
```

The data survives container restarts and removals. When upgrading the database version, stop the old container, start a new one with the same volume, and let the new version handle data migration.

Never use bind mounts for production databases — volumes have better I/O performance and are managed by Docker's storage driver.
</details>

## Security

<details>
<summary><strong>11. How do you secure a Docker container in production?</strong></summary>
<br>

Key hardening practices:
- **Run as non-root**: Use `USER` directive in the Dockerfile. Never run application processes as root.
- **Use minimal base images**: `alpine`, `distroless`, or `scratch` instead of `ubuntu`.
- **Drop capabilities**: Use `--cap-drop ALL --cap-add <only-needed>`.
- **Read-only filesystem**: Use `--read-only` and mount only specific writable paths.
- **No new privileges**: Use `--security-opt=no-new-privileges`.
- **Scan images**: Use `docker scout`, Trivy, or Snyk to detect vulnerabilities in base images and dependencies.
- **Sign images**: Use Docker Content Trust (`DOCKER_CONTENT_TRUST=1`) to verify image authenticity.
- **Limit resources**: Use `--memory`, `--cpus` to prevent resource exhaustion.
</details>

<details>
<summary><strong>12. What is a Docker rootless mode?</strong></summary>
<br>

Docker rootless mode runs the Docker daemon and containers entirely inside a user namespace, without requiring root privileges on the host. This eliminates the main security concern with Docker: that the daemon runs as root, and a container escape means root access to the host.

In rootless mode, even if an attacker escapes the container, they only get the privileges of the unprivileged user running Docker. The trade-off is that some features (like binding to ports below 1024) require additional configuration.
</details>

## Docker Compose & Orchestration

<details>
<summary><strong>13. What is the difference between docker-compose up and docker-compose run?</strong></summary>
<br>

- `docker compose up`: Starts **all** services defined in `docker-compose.yml`, creates networks/volumes, and respects `depends_on` ordering. Typically used to bring up the entire stack.
- `docker compose run <service> <command>`: Starts a **single** service with a one-off command. Does not start dependent services by default (use `--service-ports` to map ports, `--rm` to clean up). Used for running migrations, tests, or admin tasks.
</details>

<details>
<summary><strong>14. How does depends_on work and what are its limitations?</strong></summary>
<br>

`depends_on` controls **startup order** — it ensures service A starts before service B. However, it only waits for the container to **start**, not for the application inside to be **ready**.

For example, a database container might start in seconds, but PostgreSQL needs additional time to initialize. Your app container will start and immediately fail to connect.

Solution: Use `depends_on` with a `condition` and health check:

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
<summary><strong>15. When would you choose Docker Swarm vs Kubernetes?</strong></summary>
<br>

**Docker Swarm**: Built into Docker, zero additional setup. Best for small to medium deployments where simplicity matters. Uses the same Docker Compose files. Limited ecosystem and community compared to Kubernetes. Suitable for teams that don't have dedicated platform engineers.

**Kubernetes**: Industry standard for container orchestration at scale. Supports auto-scaling, rolling updates, service mesh, custom resource definitions, and a massive ecosystem (Helm, Istio, ArgoCD). Higher complexity and learning curve. Required for large-scale, multi-team, multi-cloud deployments.

Rule of thumb: If you have fewer than 20 services and a small team, Swarm is sufficient. Beyond that, Kubernetes is worth the investment.
</details>

## Production & Troubleshooting

<details>
<summary><strong>16. How do you reduce Docker image size?</strong></summary>
<br>

1. **Use multi-stage builds** — keep build tools out of the final image.
2. **Use minimal base images** — `alpine` (~5MB) instead of `ubuntu` (~75MB).
3. **Combine RUN commands** — each `RUN` creates a layer. Chain commands with `&&` and clean up in the same layer.
4. **Use .dockerignore** — exclude `node_modules`, `.git`, test files, docs from the build context.
5. **Order layers by change frequency** — put rarely-changed layers (dependencies) before frequently-changed layers (source code) to maximize cache hits.
</details>

<details>
<summary><strong>17. A container keeps restarting. How do you debug it?</strong></summary>
<br>

Step-by-step approach:
1. `docker ps -a` — check the exit code. Exit code 137 = OOM killed. Exit code 1 = application error.
2. `docker logs <container>` — read the application logs for stack traces or error messages.
3. `docker inspect <container>` — check `State.OOMKilled`, resource limits, and environment variables.
4. `docker run -it --entrypoint /bin/sh <image>` — start an interactive shell to debug the environment manually.
5. `docker stats` — check if the container is hitting memory or CPU limits.
6. Check `docker events` — look for kill signals or OOM events from the daemon.
</details>

<details>
<summary><strong>18. What is the difference between docker stop and docker kill?</strong></summary>
<br>

- `docker stop` sends **SIGTERM** to the main process (PID 1) and waits for a grace period (default 10 seconds). If the process doesn't exit, Docker sends SIGKILL. This allows the application to perform graceful shutdown (close connections, flush buffers, save state).
- `docker kill` sends **SIGKILL** immediately. The process is terminated without any chance to clean up. Use only when a container is unresponsive.

Best practice: Always use `docker stop` in production. Ensure your application handles SIGTERM properly.
</details>

<details>
<summary><strong>19. How do you handle secrets in Docker?</strong></summary>
<br>

**Never** bake secrets into images (ENV in Dockerfile, COPY of .env files). They persist in image layers and are visible with `docker history`.

Approaches by maturity level:
- **Basic**: Pass secrets via `--env-file` at runtime (file not included in image).
- **Better**: Use Docker Swarm secrets or Kubernetes secrets (mounted as files, not environment variables).
- **Best**: Use an external secrets manager (HashiCorp Vault, AWS Secrets Manager, Azure Key Vault) and inject secrets at runtime via sidecar or init container.
</details>

<details>
<summary><strong>20. What is a Docker health check and why is it critical?</strong></summary>
<br>

A health check is a command that Docker runs periodically inside the container to verify the application is actually working — not just that the process is running.

```dockerfile
HEALTHCHECK --interval=30s --timeout=5s --retries=3 \
  CMD curl -f http://localhost:3000/health || exit 1
```

Without a health check, Docker only knows if the process is alive (PID exists). With a health check, Docker knows if the application is **healthy** (responding to requests). This is critical for:
- **Load balancers**: Route traffic only to healthy containers.
- **Orchestrators**: Restart unhealthy containers automatically.
- **depends_on**: Wait for actual readiness, not just process start.
</details>
