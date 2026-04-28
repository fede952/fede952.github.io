---
title: "Diario del Capitano Docker: La Guida Definitiva ai Comandi per Container"
description: "Padroneggia Docker con questo cheatsheet completo che copre ciclo di vita dei container, gestione delle immagini, networking, volumi e Docker Compose. Comandi essenziali per ingegneri DevOps e sviluppatori."
date: 2026-02-10
tags: ["docker", "cheatsheet", "devops", "containers", "docker-compose"]
keywords: ["cheatsheet comandi docker", "esempi docker run", "tutorial docker compose", "networking container", "sintassi dockerfile", "strumenti devops", "mount volumi docker", "build immagine docker", "gestione container docker", "docker registry push pull"]
draft: false
schema_json: >
  {
    "@context": "https://schema.org",
    "@type": "TechArticle",
    "name": "Diario del Capitano Docker: La Guida Definitiva ai Comandi per Container",
    "description": "Cheatsheet completo dei comandi Docker che copre ciclo di vita dei container, gestione delle immagini, networking, volumi e Docker Compose.",
    "proficiencyLevel": "Intermediate",
    "inLanguage": "it"
  }
---

## Inizializzazione del Sistema

Docker ha cambiato il modo in cui il software viene costruito, distribuito e deployato. Invece di configurare i server manualmente e sperare che l'ambiente corrisponda alla produzione, impacchetti la tua applicazione e tutte le sue dipendenze in un container — un'unità leggera, portabile e autonoma che funziona in modo identico su qualsiasi macchina. Che tu stia deployando un'architettura a microservizi, eseguendo pipeline CI/CD o avviando ambienti di sviluppo isolati, Docker è il motore che rende tutto possibile. Questo manuale operativo contiene ogni comando necessario per gestire l'intero ciclo di vita dei container, dal pull della prima immagine all'orchestrazione di stack multi-servizio con Docker Compose.

Ogni comando è stato testato in ambienti di produzione. Copia, incolla, esegui.

---

## Ciclo di Vita dei Container

Gestire i container dalla creazione alla pulizia è il flusso di lavoro principale di Docker. Comprendere l'intero ciclo di vita — crea, avvia, ferma, riavvia, rimuovi — ti dà un controllo preciso sui tuoi carichi di lavoro in esecuzione.

### Eseguire un container

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

### Fermare e avviare container

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

### Elencare e ispezionare container

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

### Eseguire comandi nei container in esecuzione

```bash
# Open a shell inside a running container
docker exec -it my-nginx /bin/bash

# Run a single command inside a container
docker exec my-nginx cat /etc/nginx/nginx.conf

# Run as a specific user
docker exec -u root my-nginx whoami
```

### Rimuovere container

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

## Gestione delle Immagini

Le immagini Docker sono i progetti per i container. Ogni container che esegui è un'istanza di un'immagine. Capire come costruire, taggare, pushare e gestire le immagini è essenziale per qualsiasi flusso di lavoro Docker — dallo sviluppo locale alle pipeline CI/CD in produzione.

### Costruire immagini

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

### Elencare e gestire immagini

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

### Push e pull di immagini

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

Il networking dei container determina come i tuoi servizi comunicano — tra loro, con l'host e con il mondo esterno. Docker fornisce diversi driver di rete, e scegliere quello giusto è fondamentale per la sicurezza, le prestazioni e la scoperta dei servizi nelle applicazioni multi-container.

### Gestire le reti

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

### Collegare container alle reti

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

### Mappatura delle porte

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

## Volumi

I dati all'interno di un container sono effimeri — quando il container viene rimosso, i dati vengono persi. I volumi risolvono questo problema fornendo storage persistente che sopravvive agli eventi del ciclo di vita del container. Sono il meccanismo raccomandato per persistere i dati generati e utilizzati dai container Docker, che si tratti di database, upload di file o file di configurazione.

### Gestire i volumi

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

### Montare volumi nei container

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

Docker Compose è lo strumento per definire e eseguire applicazioni multi-container. Invece di eseguire più comandi `docker run` con flag complesse, definisci l'intero stack in un singolo file YAML — servizi, reti, volumi, variabili d'ambiente — e lo gestisci con comandi semplici. Questo è l'approccio standard per ambienti di sviluppo locali, stack di test e anche deployment in produzione di applicazioni di piccole e medie dimensioni.

### Comandi base

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

### Gestione dei servizi

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

### Esempio docker-compose.yml

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

## Pulizia del Sistema

Docker accumula immagini inutilizzate, container fermati e volumi orfani nel tempo. Una pulizia regolare previene problemi di spazio su disco, specialmente sui server CI/CD e sulle macchine di sviluppo dove le immagini vengono costruite frequentemente.

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
