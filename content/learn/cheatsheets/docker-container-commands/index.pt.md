---
title: "Diário de Bordo do Capitão Docker: A Referência Definitiva de Comandos para Containers"
description: "Domine o Docker com este cheatsheet abrangente cobrindo ciclo de vida de containers, gerenciamento de imagens, redes, volumes e Docker Compose. Comandos essenciais para engenheiros DevOps e desenvolvedores."
date: 2026-02-10
tags: ["docker", "cheatsheet", "devops", "containers", "docker-compose"]
keywords: ["cheatsheet comandos docker", "exemplos docker run", "tutorial docker compose", "rede de containers", "sintaxe dockerfile", "ferramentas devops", "montagem volumes docker", "build imagem docker", "gerenciamento containers docker", "docker registry push pull"]
draft: false
schema_json: >
  {
    "@context": "https://schema.org",
    "@type": "TechArticle",
    "name": "Diário de Bordo do Capitão Docker: A Referência Definitiva de Comandos para Containers",
    "description": "Cheatsheet abrangente de comandos Docker cobrindo ciclo de vida de containers, gerenciamento de imagens, redes, volumes e Docker Compose.",
    "proficiencyLevel": "Intermediate",
    "inLanguage": "pt"
  }
---

## Inicialização do Sistema

O Docker mudou a forma como o software é construído, distribuído e implantado. Em vez de configurar servidores manualmente e torcer para que o ambiente corresponda à produção, você empacota sua aplicação e todas as suas dependências em um container — uma unidade leve, portátil e autônoma que roda de forma idêntica em qualquer máquina. Seja implantando uma arquitetura de microsserviços, executando pipelines CI/CD ou criando ambientes de desenvolvimento isolados, o Docker é o motor que torna tudo possível. Este manual de campo contém cada comando que você precisa para gerenciar o ciclo de vida completo dos containers, desde baixar sua primeira imagem até orquestrar stacks multi-serviço com Docker Compose.

Cada comando foi testado em ambientes de produção. Copie, cole, execute.

---

## Ciclo de Vida dos Containers

Gerenciar containers da criação à limpeza é o fluxo de trabalho principal do Docker. Compreender o ciclo de vida completo — criar, iniciar, parar, reiniciar, remover — dá a você controle preciso sobre suas cargas de trabalho em execução.

### Executar um container

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

### Parar e iniciar containers

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

### Listar e inspecionar containers

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

### Executar comandos em containers em execução

```bash
# Open a shell inside a running container
docker exec -it my-nginx /bin/bash

# Run a single command inside a container
docker exec my-nginx cat /etc/nginx/nginx.conf

# Run as a specific user
docker exec -u root my-nginx whoami
```

### Remover containers

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

## Gerenciamento de Imagens

As imagens Docker são os projetos para containers. Cada container que você executa é uma instância de uma imagem. Entender como construir, taguear, enviar e gerenciar imagens é essencial para qualquer fluxo de trabalho Docker — do desenvolvimento local às pipelines CI/CD em produção.

### Construir imagens

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

### Listar e gerenciar imagens

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

### Enviar e baixar imagens

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

A rede de containers determina como seus serviços se comunicam — entre si, com o host e com o mundo exterior. O Docker fornece vários drivers de rede, e escolher o correto é crítico para segurança, desempenho e descoberta de serviços em aplicações multi-container.

### Gerenciar redes

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

### Conectar containers a redes

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

### Mapeamento de portas

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

Os dados dentro de um container são efêmeros — quando o container é removido, os dados se perdem. Os volumes resolvem este problema fornecendo armazenamento persistente que sobrevive aos eventos do ciclo de vida do container. Eles são o mecanismo recomendado para persistir dados gerados e usados por containers Docker, seja para bancos de dados, uploads de arquivos ou arquivos de configuração.

### Gerenciar volumes

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

### Montar volumes em containers

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

O Docker Compose é a ferramenta para definir e executar aplicações multi-container. Em vez de executar múltiplos comandos `docker run` com flags complexas, você define todo o seu stack em um único arquivo YAML — serviços, redes, volumes, variáveis de ambiente — e o gerencia com comandos simples. Esta é a abordagem padrão para ambientes de desenvolvimento local, stacks de teste e até mesmo implantações em produção de aplicações de pequeno e médio porte.

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

### Gerenciamento de serviços

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

### Exemplo docker-compose.yml

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

## Limpeza do Sistema

O Docker acumula imagens não utilizadas, containers parados e volumes órfãos ao longo do tempo. A limpeza regular previne problemas de espaço em disco, especialmente em servidores CI/CD e máquinas de desenvolvimento onde imagens são construídas frequentemente.

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
