---
title: "Docker船長の航海日誌：究極のコンテナコマンドリファレンス"
description: "コンテナのライフサイクル、イメージ管理、ネットワーキング、ボリューム、Docker Composeを網羅したこの包括的なチートシートでDockerをマスターしましょう。DevOpsエンジニアと開発者のための必須コマンド集。"
date: 2026-02-10
tags: ["docker", "cheatsheet", "devops", "containers", "docker-compose"]
keywords: ["dockerコマンドチートシート", "docker run例", "docker composeチュートリアル", "コンテナネットワーキング", "dockerfile構文", "devopsツール", "dockerボリュームマウント", "dockerイメージビルド", "dockerコンテナ管理", "dockerレジストリpush pull"]
draft: false
schema_json: >
  {
    "@context": "https://schema.org",
    "@type": "TechArticle",
    "name": "Docker船長の航海日誌：究極のコンテナコマンドリファレンス",
    "description": "コンテナのライフサイクル、イメージ管理、ネットワーキング、ボリューム、Docker Composeを網羅した包括的なDockerコマンドチートシート。",
    "proficiencyLevel": "Intermediate",
    "inLanguage": "ja"
  }
---

## システム初期化

Dockerはソフトウェアの構築、配布、デプロイの方法を一変させました。サーバーを手動で設定して本番環境と一致することを祈る代わりに、アプリケーションとすべての依存関係をコンテナにパッケージングします — どのマシンでも同一に動作する軽量でポータブルな自己完結型ユニットです。マイクロサービスアーキテクチャのデプロイ、CI/CDパイプラインの実行、隔離された開発環境の構築など、Dockerはそれらすべてを可能にするエンジンです。このフィールドマニュアルには、最初のイメージのプルからDocker Composeによるマルチサービススタックのオーケストレーションまで、コンテナのライフサイクル全体を管理するために必要なすべてのコマンドが含まれています。

すべてのコマンドは本番環境でテスト済みです。コピーして、ペーストして、実行してください。

---

## コンテナのライフサイクル

作成からクリーンアップまでのコンテナ管理は、Dockerの中核的なワークフローです。完全なライフサイクル — 作成、開始、停止、再起動、削除 — を理解することで、実行中のワークロードを正確に制御できます。

### コンテナの実行

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

### コンテナの停止と開始

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

### コンテナの一覧表示と検査

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

### 実行中のコンテナでコマンドを実行

```bash
# Open a shell inside a running container
docker exec -it my-nginx /bin/bash

# Run a single command inside a container
docker exec my-nginx cat /etc/nginx/nginx.conf

# Run as a specific user
docker exec -u root my-nginx whoami
```

### コンテナの削除

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

## イメージ管理

Dockerイメージはコンテナの設計図です。実行するすべてのコンテナはイメージのインスタンスです。イメージのビルド、タグ付け、プッシュ、管理の方法を理解することは、ローカル開発から本番CI/CDパイプラインまで、あらゆるDockerワークフローに不可欠です。

### イメージのビルド

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

### イメージの一覧表示と管理

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

### イメージのプッシュとプル

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

## ネットワーキング

コンテナネットワーキングは、サービスがどのように通信するかを決定します — 相互に、ホストと、そして外部の世界と。Dockerはいくつかのネットワークドライバーを提供しており、適切なものを選択することは、マルチコンテナアプリケーションのセキュリティ、パフォーマンス、サービスディスカバリにとって重要です。

### ネットワークの管理

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

### コンテナをネットワークに接続

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

### ポートマッピング

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

## ボリューム

コンテナ内のデータは一時的なものです — コンテナが削除されると、データも消えます。ボリュームは、コンテナのライフサイクルイベントを超えて存続する永続的なストレージを提供することでこの問題を解決します。データベース、ファイルアップロード、設定ファイルなど、Dockerコンテナによって生成・使用されるデータを永続化するための推奨メカニズムです。

### ボリュームの管理

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

### コンテナにボリュームをマウント

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

Docker Composeは、マルチコンテナアプリケーションを定義して実行するためのツールです。複雑なフラグを持つ複数の`docker run`コマンドを実行する代わりに、スタック全体を単一のYAMLファイルで定義します — サービス、ネットワーク、ボリューム、環境変数 — そしてシンプルなコマンドで管理します。これは、ローカル開発環境、テストスタック、さらには中小規模アプリケーションの本番デプロイメントのための標準的なアプローチです。

### 基本コマンド

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

### サービス管理

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

### docker-compose.ymlの例

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

## システムクリーンアップ

Dockerは時間とともに未使用のイメージ、停止したコンテナ、孤立したボリュームを蓄積します。定期的なクリーンアップにより、特にイメージが頻繁にビルドされるCI/CDサーバーや開発マシンでのディスク容量の問題を防ぎます。

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
