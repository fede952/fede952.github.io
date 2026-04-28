---
title: "Journal de Bord du Capitaine Docker : La Référence Ultime des Commandes de Conteneurs"
description: "Maîtrisez Docker avec ce cheatsheet complet couvrant le cycle de vie des conteneurs, la gestion des images, le réseau, les volumes et Docker Compose. Commandes essentielles pour les ingénieurs DevOps et les développeurs."
date: 2026-02-10
tags: ["docker", "cheatsheet", "devops", "containers", "docker-compose"]
keywords: ["cheatsheet commandes docker", "exemples docker run", "tutoriel docker compose", "réseau conteneurs", "syntaxe dockerfile", "outils devops", "montage volumes docker", "build image docker", "gestion conteneurs docker", "docker registry push pull"]
draft: false
schema_json: >
  {
    "@context": "https://schema.org",
    "@type": "TechArticle",
    "name": "Journal de Bord du Capitaine Docker : La Référence Ultime des Commandes de Conteneurs",
    "description": "Cheatsheet complet des commandes Docker couvrant le cycle de vie des conteneurs, la gestion des images, le réseau, les volumes et Docker Compose.",
    "proficiencyLevel": "Intermediate",
    "inLanguage": "fr"
  }
---

## Initialisation du Système

Docker a changé la façon dont le logiciel est construit, distribué et déployé. Au lieu de configurer des serveurs manuellement en espérant que l'environnement corresponde à la production, vous empaquetez votre application et toutes ses dépendances dans un conteneur — une unité légère, portable et autonome qui fonctionne de manière identique sur n'importe quelle machine. Que vous déployiez une architecture de microservices, exécutiez des pipelines CI/CD ou lanciez des environnements de développement isolés, Docker est le moteur qui rend tout cela possible. Ce manuel de terrain contient chaque commande dont vous avez besoin pour gérer le cycle de vie complet des conteneurs, du téléchargement de votre première image à l'orchestration de stacks multi-services avec Docker Compose.

Chaque commande a été testée en environnement de production. Copiez, collez, exécutez.

---

## Cycle de Vie des Conteneurs

Gérer les conteneurs de la création au nettoyage est le flux de travail principal de Docker. Comprendre le cycle de vie complet — créer, démarrer, arrêter, redémarrer, supprimer — vous donne un contrôle précis sur vos charges de travail en cours d'exécution.

### Exécuter un conteneur

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

### Arrêter et démarrer des conteneurs

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

### Lister et inspecter des conteneurs

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

### Exécuter des commandes dans les conteneurs en cours d'exécution

```bash
# Open a shell inside a running container
docker exec -it my-nginx /bin/bash

# Run a single command inside a container
docker exec my-nginx cat /etc/nginx/nginx.conf

# Run as a specific user
docker exec -u root my-nginx whoami
```

### Supprimer des conteneurs

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

## Gestion des Images

Les images Docker sont les plans de construction des conteneurs. Chaque conteneur que vous exécutez est une instance d'une image. Comprendre comment construire, taguer, pousser et gérer les images est essentiel pour tout flux de travail Docker — du développement local aux pipelines CI/CD en production.

### Construire des images

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

### Lister et gérer les images

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

### Pousser et télécharger des images

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

## Réseau

Le réseau des conteneurs détermine comment vos services communiquent — entre eux, avec l'hôte et avec le monde extérieur. Docker fournit plusieurs pilotes réseau, et choisir le bon est crucial pour la sécurité, les performances et la découverte de services dans les applications multi-conteneurs.

### Gérer les réseaux

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

### Connecter des conteneurs aux réseaux

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

### Mappage de ports

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

Les données à l'intérieur d'un conteneur sont éphémères — lorsque le conteneur est supprimé, les données disparaissent. Les volumes résolvent ce problème en fournissant un stockage persistant qui survit aux événements du cycle de vie du conteneur. Ils constituent le mécanisme recommandé pour persister les données générées et utilisées par les conteneurs Docker, qu'il s'agisse de bases de données, de téléchargement de fichiers ou de fichiers de configuration.

### Gérer les volumes

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

### Monter des volumes dans les conteneurs

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

Docker Compose est l'outil pour définir et exécuter des applications multi-conteneurs. Au lieu d'exécuter plusieurs commandes `docker run` avec des flags complexes, vous définissez l'ensemble de votre stack dans un seul fichier YAML — services, réseaux, volumes, variables d'environnement — et le gérez avec des commandes simples. C'est l'approche standard pour les environnements de développement locaux, les stacks de test et même les déploiements en production d'applications de petite et moyenne taille.

### Commandes de base

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

### Gestion des services

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

### Exemple docker-compose.yml

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

## Nettoyage du Système

Docker accumule des images inutilisées, des conteneurs arrêtés et des volumes orphelins au fil du temps. Un nettoyage régulier prévient les problèmes d'espace disque, en particulier sur les serveurs CI/CD et les machines de développement où les images sont construites fréquemment.

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
