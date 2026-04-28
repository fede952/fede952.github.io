---
title: "Бортовой журнал капитана Docker: Полный справочник команд для контейнеров"
description: "Освойте Docker с этим исчерпывающим справочником, охватывающим жизненный цикл контейнеров, управление образами, сетевое взаимодействие, тома и Docker Compose. Необходимые команды для DevOps-инженеров и разработчиков."
date: 2026-02-10
tags: ["docker", "cheatsheet", "devops", "containers", "docker-compose"]
keywords: ["шпаргалка команд docker", "примеры docker run", "руководство docker compose", "сеть контейнеров", "синтаксис dockerfile", "инструменты devops", "монтирование томов docker", "сборка образов docker", "управление контейнерами docker", "docker registry push pull"]
draft: false
schema_json: >
  {
    "@context": "https://schema.org",
    "@type": "TechArticle",
    "name": "Бортовой журнал капитана Docker: Полный справочник команд для контейнеров",
    "description": "Исчерпывающий справочник команд Docker, охватывающий жизненный цикл контейнеров, управление образами, сетевое взаимодействие, тома и Docker Compose.",
    "proficiencyLevel": "Intermediate",
    "inLanguage": "ru"
  }
---

## Инициализация системы

Docker изменил способ создания, доставки и развёртывания программного обеспечения. Вместо ручной настройки серверов с надеждой, что окружение совпадёт с продакшеном, вы упаковываете своё приложение и все его зависимости в контейнер — лёгкую, портативную, самодостаточную единицу, которая работает одинаково на любой машине. Будь то развёртывание микросервисной архитектуры, запуск CI/CD-пайплайнов или создание изолированных сред разработки, Docker — это движок, который делает всё это возможным. Этот полевой справочник содержит каждую команду, необходимую для управления полным жизненным циклом контейнеров, от загрузки первого образа до оркестрации многосервисных стеков с Docker Compose.

Каждая команда протестирована в производственных средах. Копируйте, вставляйте, выполняйте.

---

## Жизненный цикл контейнеров

Управление контейнерами от создания до очистки — это основной рабочий процесс Docker. Понимание полного жизненного цикла — создание, запуск, остановка, перезапуск, удаление — даёт вам точный контроль над вашими работающими нагрузками.

### Запуск контейнера

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

### Остановка и запуск контейнеров

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

### Просмотр и инспектирование контейнеров

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

### Выполнение команд в работающих контейнерах

```bash
# Open a shell inside a running container
docker exec -it my-nginx /bin/bash

# Run a single command inside a container
docker exec my-nginx cat /etc/nginx/nginx.conf

# Run as a specific user
docker exec -u root my-nginx whoami
```

### Удаление контейнеров

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

## Управление образами

Образы Docker — это чертежи для контейнеров. Каждый контейнер, который вы запускаете, является экземпляром образа. Понимание того, как собирать, тегировать, отправлять и управлять образами, необходимо для любого рабочего процесса Docker — от локальной разработки до CI/CD-пайплайнов в продакшене.

### Сборка образов

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

### Просмотр и управление образами

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

### Отправка и загрузка образов

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

## Сеть

Сеть контейнеров определяет, как ваши сервисы взаимодействуют — друг с другом, с хостом и с внешним миром. Docker предоставляет несколько сетевых драйверов, и выбор правильного критически важен для безопасности, производительности и обнаружения сервисов в многоконтейнерных приложениях.

### Управление сетями

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

### Подключение контейнеров к сетям

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

### Маппинг портов

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

## Тома

Данные внутри контейнера эфемерны — когда контейнер удаляется, данные теряются. Тома решают эту проблему, предоставляя постоянное хранилище, которое сохраняется при событиях жизненного цикла контейнера. Это рекомендуемый механизм для сохранения данных, генерируемых и используемых контейнерами Docker, будь то базы данных, загрузки файлов или файлы конфигурации.

### Управление томами

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

### Монтирование томов в контейнеры

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

Docker Compose — это инструмент для определения и запуска многоконтейнерных приложений. Вместо выполнения множества команд `docker run` со сложными флагами, вы определяете весь свой стек в одном YAML-файле — сервисы, сети, тома, переменные окружения — и управляете им простыми командами. Это стандартный подход для локальных сред разработки, тестовых стеков и даже продакшен-развёртываний небольших и средних приложений.

### Базовые команды

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

### Управление сервисами

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

### Пример docker-compose.yml

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

## Очистка системы

Docker со временем накапливает неиспользуемые образы, остановленные контейнеры и осиротевшие тома. Регулярная очистка предотвращает проблемы с дисковым пространством, особенно на CI/CD-серверах и машинах разработки, где образы создаются часто.

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
