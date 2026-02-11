---
title: "سجل قبطان Docker: المرجع الشامل لأوامر الحاويات"
description: "أتقن Docker مع هذه الورقة المرجعية الشاملة التي تغطي دورة حياة الحاويات وإدارة الصور والشبكات والأحجام و Docker Compose. أوامر أساسية لمهندسي DevOps والمطورين."
date: 2026-02-10
tags: ["docker", "cheatsheet", "devops", "containers", "docker-compose"]
keywords: ["ورقة مرجعية أوامر docker", "أمثلة docker run", "شرح docker compose", "شبكات الحاويات", "صياغة dockerfile", "أدوات devops", "تركيب أحجام docker", "بناء صور docker", "إدارة حاويات docker", "docker registry دفع وسحب"]
draft: false
schema_json: >
  {
    "@context": "https://schema.org",
    "@type": "TechArticle",
    "name": "سجل قبطان Docker: المرجع الشامل لأوامر الحاويات",
    "description": "ورقة مرجعية شاملة لأوامر Docker تغطي دورة حياة الحاويات وإدارة الصور والشبكات والأحجام و Docker Compose.",
    "proficiencyLevel": "Intermediate",
    "inLanguage": "ar"
  }
---

## تهيئة النظام

غيّر Docker الطريقة التي يُبنى بها البرنامج ويُوزَّع ويُنشَر. بدلاً من تهيئة الخوادم يدوياً والأمل في أن تتطابق البيئة مع الإنتاج، تقوم بتعبئة تطبيقك وجميع تبعياته في حاوية — وحدة خفيفة الوزن ومحمولة ومكتفية ذاتياً تعمل بشكل متطابق على أي جهاز. سواء كنت تنشر بنية خدمات مصغرة، أو تشغّل أنابيب CI/CD، أو تطلق بيئات تطوير معزولة، فإن Docker هو المحرك الذي يجعل كل ذلك ممكناً. يحتوي هذا الدليل الميداني على كل أمر تحتاجه لإدارة دورة حياة الحاويات بالكامل، من سحب أول صورة إلى تنسيق حزم متعددة الخدمات مع Docker Compose.

تم اختبار كل أمر في بيئات الإنتاج. انسخ، الصق، نفّذ.

---

## دورة حياة الحاويات

إدارة الحاويات من الإنشاء إلى التنظيف هي سير عمل Docker الأساسي. فهم دورة الحياة الكاملة — إنشاء، تشغيل، إيقاف، إعادة تشغيل، حذف — يمنحك تحكماً دقيقاً في أعباء العمل قيد التشغيل.

### تشغيل حاوية

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

### إيقاف وتشغيل الحاويات

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

### عرض وفحص الحاويات

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

### تنفيذ أوامر في الحاويات قيد التشغيل

```bash
# Open a shell inside a running container
docker exec -it my-nginx /bin/bash

# Run a single command inside a container
docker exec my-nginx cat /etc/nginx/nginx.conf

# Run as a specific user
docker exec -u root my-nginx whoami
```

### حذف الحاويات

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

## إدارة الصور

صور Docker هي المخططات الهندسية للحاويات. كل حاوية تشغّلها هي نسخة من صورة. فهم كيفية بناء الصور ووسمها ودفعها وإدارتها أمر ضروري لأي سير عمل Docker — من التطوير المحلي إلى أنابيب CI/CD في الإنتاج.

### بناء الصور

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

### عرض وإدارة الصور

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

### دفع وسحب الصور

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

## الشبكات

تحدد شبكات الحاويات كيفية تواصل خدماتك — مع بعضها البعض، ومع المضيف، ومع العالم الخارجي. يوفر Docker عدة برامج تشغيل شبكات، واختيار البرنامج الصحيح أمر حاسم للأمان والأداء واكتشاف الخدمات في التطبيقات متعددة الحاويات.

### إدارة الشبكات

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

### ربط الحاويات بالشبكات

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

### تعيين المنافذ

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

## الأحجام

البيانات داخل الحاوية مؤقتة — عندما تُحذف الحاوية، تختفي البيانات. تحل الأحجام هذه المشكلة بتوفير تخزين دائم يبقى بعد أحداث دورة حياة الحاوية. وهي الآلية الموصى بها لحفظ البيانات التي تنشئها وتستخدمها حاويات Docker، سواء كانت قواعد بيانات أو رفع ملفات أو ملفات تهيئة.

### إدارة الأحجام

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

### تركيب الأحجام في الحاويات

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

Docker Compose هو الأداة لتعريف وتشغيل التطبيقات متعددة الحاويات. بدلاً من تشغيل عدة أوامر `docker run` بعلامات معقدة، تعرّف حزمتك بالكامل في ملف YAML واحد — الخدمات، الشبكات، الأحجام، متغيرات البيئة — وتديرها بأوامر بسيطة. هذا هو النهج القياسي لبيئات التطوير المحلية وحزم الاختبار وحتى نشر الإنتاج للتطبيقات الصغيرة والمتوسطة.

### الأوامر الأساسية

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

### إدارة الخدمات

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

### مثال docker-compose.yml

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

## تنظيف النظام

يتراكم في Docker صور غير مستخدمة وحاويات متوقفة وأحجام يتيمة بمرور الوقت. التنظيف المنتظم يمنع مشاكل مساحة القرص، خاصة على خوادم CI/CD وأجهزة التطوير حيث تُبنى الصور بشكل متكرر.

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
