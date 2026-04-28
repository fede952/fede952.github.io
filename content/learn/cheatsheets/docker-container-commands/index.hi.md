---
title: "Docker कप्तान की लॉगबुक: कंटेनर कमांड की अंतिम संदर्भ गाइड"
description: "कंटेनर लाइफसाइकल, इमेज प्रबंधन, नेटवर्किंग, वॉल्यूम और Docker Compose को कवर करने वाली इस व्यापक चीटशीट के साथ Docker में महारत हासिल करें। DevOps इंजीनियरों और डेवलपर्स के लिए आवश्यक कमांड।"
date: 2026-02-10
tags: ["docker", "cheatsheet", "devops", "containers", "docker-compose"]
keywords: ["docker कमांड चीटशीट", "docker run उदाहरण", "docker compose ट्यूटोरियल", "कंटेनर नेटवर्किंग", "dockerfile सिंटैक्स", "devops टूल्स", "docker वॉल्यूम माउंट", "docker इमेज बिल्ड", "docker कंटेनर प्रबंधन", "docker registry पुश पुल"]
draft: false
schema_json: >
  {
    "@context": "https://schema.org",
    "@type": "TechArticle",
    "name": "Docker कप्तान की लॉगबुक: कंटेनर कमांड की अंतिम संदर्भ गाइड",
    "description": "कंटेनर लाइफसाइकल, इमेज प्रबंधन, नेटवर्किंग, वॉल्यूम और Docker Compose को कवर करने वाली व्यापक Docker कमांड चीटशीट।",
    "proficiencyLevel": "Intermediate",
    "inLanguage": "hi"
  }
---

## सिस्टम आरंभीकरण

Docker ने सॉफ्टवेयर के निर्माण, वितरण और तैनाती के तरीके को बदल दिया है। सर्वरों को मैन्युअल रूप से कॉन्फ़िगर करने और उम्मीद करने के बजाय कि वातावरण प्रोडक्शन से मेल खाएगा, आप अपने एप्लिकेशन और उसकी सभी निर्भरताओं को एक कंटेनर में पैकेज करते हैं — एक हल्की, पोर्टेबल, आत्मनिर्भर इकाई जो किसी भी मशीन पर समान रूप से चलती है। चाहे आप माइक्रोसर्विस आर्किटेक्चर तैनात कर रहे हों, CI/CD पाइपलाइन चला रहे हों, या अलग-थलग विकास वातावरण बना रहे हों, Docker वह इंजन है जो यह सब संभव बनाता है। इस फील्ड मैनुअल में कंटेनर के पूर्ण लाइफसाइकल को प्रबंधित करने के लिए आवश्यक हर कमांड है, पहली इमेज पुल करने से लेकर Docker Compose के साथ मल्टी-सर्विस स्टैक को ऑर्केस्ट्रेट करने तक।

हर कमांड प्रोडक्शन वातावरण में परीक्षित है। कॉपी करें, पेस्ट करें, निष्पादित करें।

---

## कंटेनर लाइफसाइकल

निर्माण से लेकर सफाई तक कंटेनरों का प्रबंधन Docker का मुख्य वर्कफ़्लो है। पूर्ण लाइफसाइकल को समझना — बनाना, शुरू करना, रोकना, पुनः शुरू करना, हटाना — आपको अपने चल रहे वर्कलोड पर सटीक नियंत्रण देता है।

### कंटेनर चलाना

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

### कंटेनर रोकना और शुरू करना

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

### कंटेनर सूचीबद्ध करना और निरीक्षण करना

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

### चल रहे कंटेनरों में कमांड निष्पादित करना

```bash
# Open a shell inside a running container
docker exec -it my-nginx /bin/bash

# Run a single command inside a container
docker exec my-nginx cat /etc/nginx/nginx.conf

# Run as a specific user
docker exec -u root my-nginx whoami
```

### कंटेनर हटाना

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

## इमेज प्रबंधन

Docker इमेज कंटेनरों के लिए ब्लूप्रिंट हैं। आप जो भी कंटेनर चलाते हैं वह एक इमेज का इंस्टेंस है। इमेज को बिल्ड, टैग, पुश और प्रबंधित करने का तरीका समझना किसी भी Docker वर्कफ़्लो के लिए आवश्यक है — स्थानीय विकास से लेकर प्रोडक्शन CI/CD पाइपलाइन तक।

### इमेज बिल्ड करना

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

### इमेज सूचीबद्ध करना और प्रबंधित करना

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

### इमेज पुश और पुल करना

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

## नेटवर्किंग

कंटेनर नेटवर्किंग यह निर्धारित करती है कि आपकी सेवाएं कैसे संवाद करती हैं — एक-दूसरे के साथ, होस्ट के साथ और बाहरी दुनिया के साथ। Docker कई नेटवर्क ड्राइवर प्रदान करता है, और सही ड्राइवर चुनना मल्टी-कंटेनर एप्लिकेशन में सुरक्षा, प्रदर्शन और सर्विस डिस्कवरी के लिए महत्वपूर्ण है।

### नेटवर्क प्रबंधित करना

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

### कंटेनरों को नेटवर्क से जोड़ना

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

### पोर्ट मैपिंग

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

## वॉल्यूम

कंटेनर के अंदर का डेटा अस्थायी होता है — जब कंटेनर हटाया जाता है, तो डेटा भी चला जाता है। वॉल्यूम इस समस्या को हल करते हैं, स्थायी स्टोरेज प्रदान करके जो कंटेनर लाइफसाइकल इवेंट्स के बाद भी बना रहता है। डेटाबेस, फ़ाइल अपलोड या कॉन्फ़िगरेशन फ़ाइलों के लिए Docker कंटेनरों द्वारा उत्पन्न और उपयोग किए जाने वाले डेटा को स्थायी बनाने के लिए यह अनुशंसित तंत्र है।

### वॉल्यूम प्रबंधित करना

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

### कंटेनरों में वॉल्यूम माउंट करना

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

Docker Compose मल्टी-कंटेनर एप्लिकेशन को परिभाषित और चलाने का टूल है। जटिल फ़्लैग के साथ कई `docker run` कमांड चलाने के बजाय, आप अपने पूरे स्टैक को एक एकल YAML फ़ाइल में परिभाषित करते हैं — सेवाएं, नेटवर्क, वॉल्यूम, एनवायरनमेंट वेरिएबल — और इसे सरल कमांड से प्रबंधित करते हैं। यह स्थानीय विकास वातावरण, परीक्षण स्टैक और यहां तक कि छोटे से मध्यम आकार के एप्लिकेशन के प्रोडक्शन डिप्लॉयमेंट के लिए मानक दृष्टिकोण है।

### बुनियादी कमांड

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

### सेवा प्रबंधन

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

### docker-compose.yml उदाहरण

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

## सिस्टम सफाई

Docker समय के साथ अप्रयुक्त इमेज, रुके हुए कंटेनर और अनाथ वॉल्यूम जमा करता है। नियमित सफाई डिस्क स्पेस की समस्याओं को रोकती है, विशेष रूप से CI/CD सर्वर और विकास मशीनों पर जहां इमेज बार-बार बिल्ड की जाती हैं।

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
