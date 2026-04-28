---
title: "Docker船长日志：终极容器命令参考手册"
description: "通过这份全面的速查表掌握Docker，涵盖容器生命周期、镜像管理、网络、卷和Docker Compose。DevOps工程师和开发者的必备命令集。"
date: 2026-02-10
tags: ["docker", "cheatsheet", "devops", "containers", "docker-compose"]
keywords: ["docker命令速查表", "docker run示例", "docker compose教程", "容器网络", "dockerfile语法", "devops工具", "docker卷挂载", "docker镜像构建", "docker容器管理", "docker registry推送拉取"]
draft: false
schema_json: >
  {
    "@context": "https://schema.org",
    "@type": "TechArticle",
    "name": "Docker船长日志：终极容器命令参考手册",
    "description": "全面的Docker命令速查表，涵盖容器生命周期、镜像管理、网络、卷和Docker Compose。",
    "proficiencyLevel": "Intermediate",
    "inLanguage": "zh-CN"
  }
---

## 系统初始化

Docker改变了软件构建、分发和部署的方式。你不再需要手动配置服务器并祈祷环境与生产环境一致，而是将应用程序及其所有依赖打包到一个容器中——一个轻量级、可移植、自包含的单元，在任何机器上都能以相同的方式运行。无论你是部署微服务架构、运行CI/CD流水线，还是搭建隔离的开发环境，Docker都是让这一切成为可能的引擎。这份实战手册包含了你管理容器完整生命周期所需的每一个命令，从拉取第一个镜像到使用Docker Compose编排多服务栈。

每个命令都已在生产环境中经过测试。复制、粘贴、执行。

---

## 容器生命周期

从创建到清理的容器管理是Docker的核心工作流程。理解完整的生命周期——创建、启动、停止、重启、删除——让你能够精确控制正在运行的工作负载。

### 运行容器

```bash
# Run a container in the foreground from an image
docker run nginx

# Run in detached mode (background) with a custom name
docker run -d --name my-nginx nginx

# Run with port mapping (host:container)
docker run -d -p 8080:80 nginx

# Run with environment variables
docker run -d -e MYSQL_ROOT_PASSWORD=secret mysql:8

# Run interactively with a shell
docker run -it ubuntu /bin/bash

# Run with automatic removal after exit
docker run --rm alpine echo "hello world"
```

### 停止和启动容器

```bash
# Stop a running container gracefully (SIGTERM, then SIGKILL after timeout)
docker stop my-nginx

# Start a stopped container
docker start my-nginx

# Restart a container
docker restart my-nginx

# Kill a container immediately (SIGKILL)
docker kill my-nginx
```

### 列出和检查容器

```bash
# List running containers
docker ps

# List all containers (including stopped)
docker ps -a

# Inspect container details (JSON output)
docker inspect my-nginx

# View container logs
docker logs my-nginx

# Follow logs in real-time
docker logs -f --tail 100 my-nginx

# View resource usage statistics
docker stats
```

### 在运行中的容器中执行命令

```bash
# Open a shell inside a running container
docker exec -it my-nginx /bin/bash

# Run a single command inside a container
docker exec my-nginx cat /etc/nginx/nginx.conf

# Run as a specific user
docker exec -u root my-nginx whoami
```

### 删除容器

```bash
# Remove a stopped container
docker rm my-nginx

# Force remove a running container
docker rm -f my-nginx

# Remove all stopped containers
docker container prune

# Remove all containers (stopped and running)
docker rm -f $(docker ps -aq)
```

---

## 镜像管理

Docker镜像是容器的蓝图。你运行的每个容器都是一个镜像的实例。了解如何构建、标记、推送和管理镜像对于任何Docker工作流程都至关重要——从本地开发到生产环境的CI/CD流水线。

### 构建镜像

```bash
# Build an image from a Dockerfile in the current directory
docker build -t myapp:latest .

# Build with a specific Dockerfile
docker build -f Dockerfile.prod -t myapp:prod .

# Build with build arguments
docker build --build-arg VERSION=1.0 -t myapp:1.0 .

# Build with no cache (force rebuild all layers)
docker build --no-cache -t myapp:latest .
```

### 列出和管理镜像

```bash
# List all local images
docker images

# Remove an image
docker rmi myapp:latest

# Remove all unused images
docker image prune -a

# Tag an image for a registry
docker tag myapp:latest registry.example.com/myapp:latest

# View image history (layers)
docker history myapp:latest
```

### 推送和拉取镜像

```bash
# Pull an image from Docker Hub
docker pull nginx:alpine

# Login to a registry
docker login registry.example.com

# Push an image to a registry
docker push registry.example.com/myapp:latest

# Save an image to a tar archive
docker save -o myapp.tar myapp:latest

# Load an image from a tar archive
docker load -i myapp.tar
```

---

## 网络

容器网络决定了你的服务如何通信——彼此之间、与主机之间以及与外部世界之间。Docker提供了多种网络驱动，选择正确的驱动对于多容器应用的安全性、性能和服务发现至关重要。

### 管理网络

```bash
# List all networks
docker network ls

# Create a custom bridge network
docker network create my-network

# Create a network with a specific subnet
docker network create --subnet=172.20.0.0/16 my-network

# Inspect a network
docker network inspect my-network

# Remove a network
docker network rm my-network
```

### 将容器连接到网络

```bash
# Run a container on a specific network
docker run -d --network my-network --name app1 nginx

# Connect a running container to a network
docker network connect my-network app1

# Disconnect a container from a network
docker network disconnect my-network app1

# Run two containers on the same network (they can reach each other by name)
docker run -d --network my-network --name backend node:20
docker run -d --network my-network --name frontend nginx
# frontend can reach backend at http://backend:3000
```

### 端口映射

```bash
# Map a specific host port to container port
docker run -d -p 3000:3000 myapp

# Map to all interfaces
docker run -d -p 0.0.0.0:3000:3000 myapp

# Map a random host port
docker run -d -p 3000 myapp

# Map multiple ports
docker run -d -p 80:80 -p 443:443 nginx
```

---

## 卷

容器内的数据是临时的——当容器被删除时，数据也随之消失。卷通过提供在容器生命周期事件中持久存在的存储来解决这个问题。它们是持久化Docker容器生成和使用的数据的推荐机制，无论是数据库、文件上传还是配置文件。

### 管理卷

```bash
# Create a named volume
docker volume create my-data

# List all volumes
docker volume ls

# Inspect a volume
docker volume inspect my-data

# Remove a volume
docker volume rm my-data

# Remove all unused volumes
docker volume prune
```

### 将卷挂载到容器

```bash
# Mount a named volume
docker run -d -v my-data:/var/lib/mysql mysql:8

# Bind mount a host directory
docker run -d -v /host/path:/container/path nginx

# Mount as read-only
docker run -d -v my-data:/data:ro myapp

# Use tmpfs mount (in-memory, not persisted)
docker run -d --tmpfs /tmp myapp
```

---

## Docker Compose

Docker Compose是用于定义和运行多容器应用的工具。你不需要运行带有复杂标志的多个`docker run`命令，而是在单个YAML文件中定义整个栈——服务、网络、卷、环境变量——并用简单的命令来管理。这是本地开发环境、测试栈乃至中小型应用生产部署的标准方法。

### 基本命令

```bash
# Start all services defined in docker-compose.yml
docker compose up -d

# Stop all services
docker compose down

# Stop and remove volumes
docker compose down -v

# Rebuild images before starting
docker compose up -d --build

# View running services
docker compose ps

# View logs for all services
docker compose logs

# Follow logs for a specific service
docker compose logs -f backend

# Scale a service to multiple instances
docker compose up -d --scale worker=3
```

### 服务管理

```bash
# Restart a specific service
docker compose restart backend

# Execute a command in a running service
docker compose exec backend bash

# Run a one-off command in a new container
docker compose run --rm backend python manage.py migrate

# Pull latest images for all services
docker compose pull

# View the resolved compose configuration
docker compose config
```

### docker-compose.yml示例

```yaml
# Multi-service stack: web app + database + cache
services:
  app:
    build: .
    ports:
      - "3000:3000"
    environment:
      - DATABASE_URL=postgres://user:pass@db:5432/mydb
      - REDIS_URL=redis://cache:6379
    depends_on:
      - db
      - cache
    volumes:
      - ./src:/app/src

  db:
    image: postgres:16
    environment:
      POSTGRES_USER: user
      POSTGRES_PASSWORD: pass
      POSTGRES_DB: mydb
    volumes:
      - pgdata:/var/lib/postgresql/data

  cache:
    image: redis:7-alpine
    ports:
      - "6379:6379"

volumes:
  pgdata:
```

---

## 系统清理

Docker会随着时间积累未使用的镜像、停止的容器和孤立的卷。定期清理可以防止磁盘空间问题，特别是在频繁构建镜像的CI/CD服务器和开发机器上。

```bash
# Remove all stopped containers, unused networks, dangling images, and build cache
docker system prune

# Remove everything including unused images (aggressive cleanup)
docker system prune -a --volumes

# View disk usage by Docker
docker system df

# View detailed disk usage
docker system df -v
```
