---
title: "Docker Kapitäns-Logbuch: Die Ultimative Befehlsreferenz für Container"
description: "Meistern Sie Docker mit diesem umfassenden Cheatsheet, das den Container-Lebenszyklus, Image-Verwaltung, Netzwerke, Volumes und Docker Compose abdeckt. Wesentliche Befehle für DevOps-Ingenieure und Entwickler."
date: 2026-02-10
tags: ["docker", "cheatsheet", "devops", "containers", "docker-compose"]
keywords: ["docker befehle cheatsheet", "docker run beispiele", "docker compose tutorial", "container netzwerk", "dockerfile syntax", "devops werkzeuge", "docker volume mount", "docker image build", "docker container verwaltung", "docker registry push pull"]
draft: false
schema_json: >
  {
    "@context": "https://schema.org",
    "@type": "TechArticle",
    "name": "Docker Kapitäns-Logbuch: Die Ultimative Befehlsreferenz für Container",
    "description": "Umfassendes Docker-Befehlscheatsheet, das den Container-Lebenszyklus, Image-Verwaltung, Netzwerke, Volumes und Docker Compose abdeckt.",
    "proficiencyLevel": "Intermediate",
    "inLanguage": "de"
  }
---

## Systeminitialisierung

Docker hat die Art und Weise verändert, wie Software gebaut, ausgeliefert und bereitgestellt wird. Anstatt Server manuell zu konfigurieren und zu hoffen, dass die Umgebung mit der Produktion übereinstimmt, verpacken Sie Ihre Anwendung und alle ihre Abhängigkeiten in einen Container — eine leichtgewichtige, portable, eigenständige Einheit, die auf jeder Maschine identisch läuft. Ob Sie eine Microservice-Architektur bereitstellen, CI/CD-Pipelines ausführen oder isolierte Entwicklungsumgebungen hochfahren, Docker ist der Motor, der es möglich macht. Dieses Feldhandbuch enthält jeden Befehl, den Sie benötigen, um den gesamten Container-Lebenszyklus zu verwalten, vom Herunterladen Ihres ersten Images bis zur Orchestrierung von Multi-Service-Stacks mit Docker Compose.

Jeder Befehl wurde in Produktionsumgebungen getestet. Kopieren, einfügen, ausführen.

---

## Container-Lebenszyklus

Die Verwaltung von Containern von der Erstellung bis zur Bereinigung ist der zentrale Docker-Workflow. Das Verständnis des gesamten Lebenszyklus — erstellen, starten, stoppen, neustarten, entfernen — gibt Ihnen präzise Kontrolle über Ihre laufenden Workloads.

### Einen Container ausführen

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

### Container stoppen und starten

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

### Container auflisten und inspizieren

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

### Befehle in laufenden Containern ausführen

```bash
# Open a shell inside a running container
docker exec -it my-nginx /bin/bash

# Run a single command inside a container
docker exec my-nginx cat /etc/nginx/nginx.conf

# Run as a specific user
docker exec -u root my-nginx whoami
```

### Container entfernen

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

## Image-Verwaltung

Docker-Images sind die Baupläne für Container. Jeder Container, den Sie ausführen, ist eine Instanz eines Images. Zu verstehen, wie man Images baut, taggt, pusht und verwaltet, ist für jeden Docker-Workflow unerlässlich — von der lokalen Entwicklung bis zu CI/CD-Pipelines in der Produktion.

### Images erstellen

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

### Images auflisten und verwalten

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

### Images pushen und pullen

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

## Netzwerke

Container-Netzwerke bestimmen, wie Ihre Dienste kommunizieren — untereinander, mit dem Host und mit der Außenwelt. Docker bietet mehrere Netzwerktreiber, und die richtige Wahl ist entscheidend für Sicherheit, Leistung und Service-Erkennung in Multi-Container-Anwendungen.

### Netzwerke verwalten

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

### Container mit Netzwerken verbinden

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

### Port-Mapping

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

Daten innerhalb eines Containers sind flüchtig — wenn der Container entfernt wird, sind die Daten weg. Volumes lösen dieses Problem, indem sie persistenten Speicher bereitstellen, der die Lebenszyklus-Ereignisse des Containers überlebt. Sie sind der empfohlene Mechanismus zum Persistieren von Daten, die von Docker-Containern erzeugt und verwendet werden, sei es für Datenbanken, Datei-Uploads oder Konfigurationsdateien.

### Volumes verwalten

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

### Volumes in Container einbinden

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

Docker Compose ist das Werkzeug zum Definieren und Ausführen von Multi-Container-Anwendungen. Anstatt mehrere `docker run`-Befehle mit komplexen Flags auszuführen, definieren Sie Ihren gesamten Stack in einer einzigen YAML-Datei — Dienste, Netzwerke, Volumes, Umgebungsvariablen — und verwalten ihn mit einfachen Befehlen. Dies ist der Standardansatz für lokale Entwicklungsumgebungen, Test-Stacks und sogar Produktionsbereitstellungen kleiner bis mittlerer Anwendungen.

### Grundlegende Befehle

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

### Dienstverwaltung

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

### Beispiel docker-compose.yml

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

## Systembereinigung

Docker sammelt mit der Zeit ungenutzte Images, gestoppte Container und verwaiste Volumes an. Regelmäßige Bereinigung verhindert Speicherplatzprobleme, besonders auf CI/CD-Servern und Entwicklungsmaschinen, auf denen häufig Images gebaut werden.

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
