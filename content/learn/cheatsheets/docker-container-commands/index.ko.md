---
title: "Docker 선장의 항해일지: 궁극의 컨테이너 명령어 레퍼런스"
description: "컨테이너 라이프사이클, 이미지 관리, 네트워킹, 볼륨, Docker Compose를 다루는 이 포괄적인 치트시트로 Docker를 마스터하세요. DevOps 엔지니어와 개발자를 위한 필수 명령어 모음."
date: 2026-02-10
tags: ["docker", "cheatsheet", "devops", "containers", "docker-compose"]
keywords: ["docker 명령어 치트시트", "docker run 예제", "docker compose 튜토리얼", "컨테이너 네트워킹", "dockerfile 문법", "devops 도구", "docker 볼륨 마운트", "docker 이미지 빌드", "docker 컨테이너 관리", "docker 레지스트리 push pull"]
draft: false
schema_json: >
  {
    "@context": "https://schema.org",
    "@type": "TechArticle",
    "name": "Docker 선장의 항해일지: 궁극의 컨테이너 명령어 레퍼런스",
    "description": "컨테이너 라이프사이클, 이미지 관리, 네트워킹, 볼륨, Docker Compose를 다루는 포괄적인 Docker 명령어 치트시트.",
    "proficiencyLevel": "Intermediate",
    "inLanguage": "ko"
  }
---

## 시스템 초기화

Docker는 소프트웨어를 구축, 배포, 운영하는 방식을 변화시켰습니다. 서버를 수동으로 구성하고 환경이 프로덕션과 일치하길 바라는 대신, 애플리케이션과 모든 종속성을 컨테이너로 패키징합니다 — 어떤 머신에서든 동일하게 실행되는 경량, 이식 가능한 자체 완결형 유닛입니다. 마이크로서비스 아키텍처를 배포하든, CI/CD 파이프라인을 실행하든, 격리된 개발 환경을 구축하든, Docker는 이 모든 것을 가능하게 하는 엔진입니다. 이 현장 매뉴얼에는 첫 번째 이미지 풀부터 Docker Compose로 멀티 서비스 스택을 오케스트레이션하는 것까지, 컨테이너의 전체 라이프사이클을 관리하는 데 필요한 모든 명령어가 포함되어 있습니다.

모든 명령어는 프로덕션 환경에서 테스트되었습니다. 복사하고, 붙여넣고, 실행하세요.

---

## 컨테이너 라이프사이클

생성부터 정리까지 컨테이너를 관리하는 것은 Docker의 핵심 워크플로우입니다. 전체 라이프사이클 — 생성, 시작, 중지, 재시작, 제거 — 을 이해하면 실행 중인 워크로드를 정밀하게 제어할 수 있습니다.

### 컨테이너 실행

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

### 컨테이너 중지 및 시작

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

### 컨테이너 목록 조회 및 검사

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

### 실행 중인 컨테이너에서 명령어 실행

```bash
# Open a shell inside a running container
docker exec -it my-nginx /bin/bash

# Run a single command inside a container
docker exec my-nginx cat /etc/nginx/nginx.conf

# Run as a specific user
docker exec -u root my-nginx whoami
```

### 컨테이너 제거

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

## 이미지 관리

Docker 이미지는 컨테이너의 청사진입니다. 실행하는 모든 컨테이너는 이미지의 인스턴스입니다. 이미지를 빌드, 태그, 푸시, 관리하는 방법을 이해하는 것은 로컬 개발부터 프로덕션 CI/CD 파이프라인까지 모든 Docker 워크플로우에 필수적입니다.

### 이미지 빌드

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

### 이미지 목록 조회 및 관리

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

### 이미지 푸시 및 풀

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

## 네트워킹

컨테이너 네트워킹은 서비스가 어떻게 통신하는지를 결정합니다 — 서로 간에, 호스트와, 그리고 외부 세계와. Docker는 여러 네트워크 드라이버를 제공하며, 올바른 것을 선택하는 것은 멀티 컨테이너 애플리케이션의 보안, 성능, 서비스 디스커버리에 매우 중요합니다.

### 네트워크 관리

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

### 컨테이너를 네트워크에 연결

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

### 포트 매핑

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

## 볼륨

컨테이너 내부의 데이터는 일시적입니다 — 컨테이너가 제거되면 데이터도 사라집니다. 볼륨은 컨테이너 라이프사이클 이벤트를 넘어 지속되는 영구 스토리지를 제공함으로써 이 문제를 해결합니다. 데이터베이스, 파일 업로드, 설정 파일 등 Docker 컨테이너에 의해 생성되고 사용되는 데이터를 영속화하기 위한 권장 메커니즘입니다.

### 볼륨 관리

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

### 컨테이너에 볼륨 마운트

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

Docker Compose는 멀티 컨테이너 애플리케이션을 정의하고 실행하기 위한 도구입니다. 복잡한 플래그가 포함된 여러 `docker run` 명령어를 실행하는 대신, 전체 스택을 단일 YAML 파일로 정의합니다 — 서비스, 네트워크, 볼륨, 환경 변수 — 그리고 간단한 명령어로 관리합니다. 이것은 로컬 개발 환경, 테스트 스택, 그리고 중소규모 애플리케이션의 프로덕션 배포를 위한 표준 접근 방식입니다.

### 기본 명령어

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

### 서비스 관리

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

### docker-compose.yml 예제

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

## 시스템 정리

Docker는 시간이 지남에 따라 사용하지 않는 이미지, 중지된 컨테이너, 고아 볼륨을 축적합니다. 정기적인 정리는 디스크 공간 문제를 방지하며, 특히 이미지가 자주 빌드되는 CI/CD 서버와 개발 머신에서 중요합니다.

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
