---
title: "Bitácora del Capitán Docker: La Referencia Definitiva de Comandos para Contenedores"
description: "Domina Docker con este cheatsheet completo que cubre el ciclo de vida de contenedores, gestión de imágenes, redes, volúmenes y Docker Compose. Comandos esenciales para ingenieros DevOps y desarrolladores."
date: 2026-02-10
tags: ["docker", "cheatsheet", "devops", "containers", "docker-compose"]
keywords: ["cheatsheet comandos docker", "ejemplos docker run", "tutorial docker compose", "redes de contenedores", "sintaxis dockerfile", "herramientas devops", "montaje volúmenes docker", "build imagen docker", "gestión contenedores docker", "docker registry push pull"]
draft: false
schema_json: >
  {
    "@context": "https://schema.org",
    "@type": "TechArticle",
    "name": "Bitácora del Capitán Docker: La Referencia Definitiva de Comandos para Contenedores",
    "description": "Cheatsheet completo de comandos Docker que cubre el ciclo de vida de contenedores, gestión de imágenes, redes, volúmenes y Docker Compose.",
    "proficiencyLevel": "Intermediate",
    "inLanguage": "es"
  }
---

## Inicialización del Sistema

Docker cambió la forma en que el software se construye, distribuye y despliega. En lugar de configurar servidores manualmente y esperar que el entorno coincida con producción, empaquetas tu aplicación y todas sus dependencias en un contenedor — una unidad ligera, portable y autónoma que se ejecuta de forma idéntica en cualquier máquina. Ya sea que estés desplegando una arquitectura de microservicios, ejecutando pipelines CI/CD o levantando entornos de desarrollo aislados, Docker es el motor que lo hace posible. Este manual de campo contiene cada comando que necesitas para gestionar el ciclo de vida completo de los contenedores, desde descargar tu primera imagen hasta orquestar stacks multi-servicio con Docker Compose.

Cada comando ha sido probado en entornos de producción. Copia, pega, ejecuta.

---

## Ciclo de Vida de Contenedores

Gestionar contenedores desde la creación hasta la limpieza es el flujo de trabajo principal de Docker. Comprender el ciclo de vida completo — crear, iniciar, detener, reiniciar, eliminar — te da un control preciso sobre tus cargas de trabajo en ejecución.

### Ejecutar un contenedor

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

### Detener e iniciar contenedores

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

### Listar e inspeccionar contenedores

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

### Ejecutar comandos en contenedores en ejecución

```bash
# Open a shell inside a running container
docker exec -it my-nginx /bin/bash

# Run a single command inside a container
docker exec my-nginx cat /etc/nginx/nginx.conf

# Run as a specific user
docker exec -u root my-nginx whoami
```

### Eliminar contenedores

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

## Gestión de Imágenes

Las imágenes Docker son los planos para los contenedores. Cada contenedor que ejecutas es una instancia de una imagen. Comprender cómo construir, etiquetar, subir y gestionar imágenes es esencial para cualquier flujo de trabajo Docker — desde el desarrollo local hasta las pipelines CI/CD en producción.

### Construir imágenes

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

### Listar y gestionar imágenes

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

### Subir y descargar imágenes

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

## Redes

La red de contenedores determina cómo se comunican tus servicios — entre sí, con el host y con el mundo exterior. Docker proporciona varios controladores de red, y elegir el correcto es crítico para la seguridad, el rendimiento y el descubrimiento de servicios en aplicaciones multi-contenedor.

### Gestionar redes

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

### Conectar contenedores a redes

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

### Mapeo de puertos

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

## Volúmenes

Los datos dentro de un contenedor son efímeros — cuando el contenedor se elimina, los datos desaparecen. Los volúmenes resuelven este problema proporcionando almacenamiento persistente que sobrevive a los eventos del ciclo de vida del contenedor. Son el mecanismo recomendado para persistir datos generados y utilizados por los contenedores Docker, ya sea para bases de datos, subida de archivos o archivos de configuración.

### Gestionar volúmenes

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

### Montar volúmenes en contenedores

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

Docker Compose es la herramienta para definir y ejecutar aplicaciones multi-contenedor. En lugar de ejecutar múltiples comandos `docker run` con flags complejas, defines todo tu stack en un único archivo YAML — servicios, redes, volúmenes, variables de entorno — y lo gestionas con comandos simples. Este es el enfoque estándar para entornos de desarrollo local, stacks de pruebas e incluso despliegues en producción de aplicaciones pequeñas y medianas.

### Comandos básicos

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

### Gestión de servicios

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

### Ejemplo docker-compose.yml

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

## Limpieza del Sistema

Docker acumula imágenes sin usar, contenedores detenidos y volúmenes huérfanos con el tiempo. Una limpieza regular previene problemas de espacio en disco, especialmente en servidores CI/CD y máquinas de desarrollo donde las imágenes se construyen frecuentemente.

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
