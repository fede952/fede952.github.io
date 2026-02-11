---
title: "Docker Captain's Log: The Ultimate Container Command Reference"
description: "Master Docker with this comprehensive cheatsheet covering container lifecycle, image management, networking, volumes, and Docker Compose. Essential commands for DevOps engineers and developers."
date: 2026-02-10
tags: ["docker", "cheatsheet", "devops", "containers", "docker-compose"]
keywords: ["docker commands cheatsheet", "docker run examples", "docker compose tutorial", "container networking", "dockerfile syntax", "devops tools", "docker volume mount", "docker image build", "docker container management", "docker registry push pull"]
draft: false
schema_json: >
  {
    "@context": "https://schema.org",
    "@type": "TechArticle",
    "name": "Docker Captain's Log: The Ultimate Container Command Reference",
    "description": "Comprehensive Docker command cheatsheet covering container lifecycle, image management, networking, volumes, and Docker Compose.",
    "proficiencyLevel": "Intermediate",
    "inLanguage": "en"
  }
---

## System Init

Docker changed the way software is built, shipped, and deployed. Instead of configuring servers manually and hoping the environment matches production, you package your application and all its dependencies into a container — a lightweight, portable, self-contained unit that runs identically on any machine. Whether you are deploying a microservice architecture, running CI/CD pipelines, or spinning up isolated development environments, Docker is the engine that makes it possible. This field manual contains every command you need to manage the full container lifecycle, from pulling your first image to orchestrating multi-service stacks with Docker Compose.

Every command has been tested in production environments. Copy, paste, execute.

---

## Container Lifecycle

Managing containers from creation to cleanup is the core Docker workflow. Understanding the full lifecycle — create, start, stop, restart, remove — gives you precise control over your running workloads.

### Run a container

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

### Stop and start containers

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

### List and inspect containers

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

### Execute commands in running containers

```bash
# Open a shell inside a running container
docker exec -it my-nginx /bin/bash

# Run a single command inside a container
docker exec my-nginx cat /etc/nginx/nginx.conf

# Run as a specific user
docker exec -u root my-nginx whoami
```

### Remove containers

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

## Image Management

Docker images are the blueprints for containers. Every container you run is an instance of an image. Understanding how to build, tag, push, and manage images is essential for any Docker workflow — from local development to production CI/CD pipelines.

### Build images

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

### List and manage images

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

### Push and pull images

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

## Networking

Container networking determines how your services communicate — with each other, with the host, and with the outside world. Docker provides several network drivers, and choosing the right one is critical for security, performance, and service discovery in multi-container applications.

### Manage networks

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

### Connect containers to networks

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

### Port mapping

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

## Volumes

Data inside a container is ephemeral — when the container is removed, the data is gone. Volumes solve this problem by providing persistent storage that survives container lifecycle events. They are the recommended mechanism for persisting data generated by and used by Docker containers, whether for databases, file uploads, or configuration files.

### Manage volumes

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

### Mount volumes to containers

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

Docker Compose is the tool for defining and running multi-container applications. Instead of running multiple `docker run` commands with complex flags, you define your entire stack in a single YAML file — services, networks, volumes, environment variables — and manage it with simple commands. This is the standard approach for local development environments, testing stacks, and even production deployments of small to medium applications.

### Basic commands

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

### Service management

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

### Example docker-compose.yml

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

## System Cleanup

Docker accumulates unused images, stopped containers, and orphaned volumes over time. Regular cleanup prevents disk space issues, especially on CI/CD servers and development machines where images are built frequently.

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
