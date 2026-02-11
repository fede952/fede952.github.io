---
title: "ИСПРАВЛЕНИЕ: Cannot connect to the Docker daemon at unix:///var/run/docker.sock"
description: "Решите ошибку 'Cannot connect to the Docker daemon' за считанные секунды. Узнайте, проблема ли это сервиса или прав доступа, и исправьте её навсегда."
date: 2026-02-11
tags: ["docker", "debug", "linux", "devops"]
keywords: ["cannot connect to the docker daemon", "docker daemon not running", "docker.sock permission denied", "var run docker.sock", "is the docker daemon running", "docker service start", "docker permission denied", "docker socket error", "sudo docker fix", "docker usermod group"]
draft: false
schema_json: >
  {
    "@context": "https://schema.org",
    "@type": "TechArticle",
    "name": "ИСПРАВЛЕНИЕ: Cannot connect to the Docker daemon at unix:///var/run/docker.sock",
    "description": "Пошаговое исправление ошибки подключения к Docker daemon в Linux.",
    "proficiencyLevel": "Beginner",
    "inLanguage": "ru"
  }
---

## Ошибка

Вы выполняете команду Docker и получаете следующее:

```
Cannot connect to the Docker daemon at unix:///var/run/docker.sock. Is the docker daemon running?
```

Или вариацию:

```
Got permission denied while trying to connect to the Docker daemon socket at unix:///var/run/docker.sock
```

Это одна из самых распространённых ошибок Docker в Linux. Она означает, что ваша оболочка не может связаться с движком Docker. Причина всегда одна из двух: служба Docker не запущена или у вашего пользователя нет прав доступа к сокету Docker.

---

## Быстрое Исправление

### 1. Запустите службу Docker

Возможно, демон просто не запущен. Запустите его:

```bash
# Start Docker now
sudo systemctl start docker

# Enable Docker to start on boot
sudo systemctl enable docker

# Verify it's running
sudo systemctl status docker
```

Если `status` показывает `active (running)`, служба работает. Попробуйте выполнить команду Docker снова.

### 2. Исправьте права пользователя

Если служба запущена, но вы всё ещё получаете "permission denied", ваш пользователь не входит в группу `docker`:

```bash
# Add your user to the docker group
sudo usermod -aG docker $USER

# Apply the new group membership (or log out and back in)
newgrp docker

# Verify you're in the group
groups
```

После этого вы сможете выполнять `docker ps` без `sudo`.

---

## Объяснение

Docker использует Unix-сокет (`/var/run/docker.sock`) для связи между CLI-клиентом и демоном Docker (фоновой службой). Для корректной работы должны выполняться два условия:

**1. Демон Docker должен быть запущен.** Служба systemd `docker.service` управляет демоном. Если машина только что загрузилась и Docker не включён в автозапуск, или если служба аварийно завершилась, файл сокета либо не существует, либо не принимает подключения.

**2. Ваш пользователь должен иметь доступ к сокету.** По умолчанию сокет Docker принадлежит `root:docker` с правами `srw-rw----`. Это означает, что только root и члены группы `docker` могут читать/писать в него. Если ваш пользователь не входит в группу `docker`, каждая команда требует `sudo`.

### Как определить проблему?

```bash
# Check if the service is running
systemctl is-active docker

# Check socket permissions
ls -la /var/run/docker.sock

# Check if your user is in the docker group
groups $USER
```

Если `systemctl is-active` возвращает `inactive` → это **проблема службы** (Исправление #1).
Если служба `active`, но вы получаете permission denied → это **проблема прав доступа** (Исправление #2).

---

## Распространённые Ловушки

- **Docker, установленный через Snap**: Если вы установили Docker через Snap вместо официального репозитория, путь к сокету и имя службы могут отличаться. Удалите версию Snap и используйте официальные пакеты Docker CE.
- **WSL2 в Windows**: Демон Docker не работает нативно в WSL2. Вам нужен запущенный Docker Desktop для Windows, или необходимо установить и запустить демон внутри вашего дистрибутива WSL2 вручную.
- **Docker Desktop на Mac/Linux**: Если вы используете Docker Desktop, демон управляется приложением Desktop, а не systemd. Убедитесь, что Docker Desktop открыт и работает.

---

## Связанные Ресурсы

Предотвратите повторение этой ошибки. Сохраните в закладки наш полный [Docker Captain's Log Cheatsheet](/cheatsheets/docker-container-commands/) — он охватывает права пользователей, управление службами и все команды `docker`, необходимые в продакшене.

Нужно управлять службами и пользователями Linux? Смотрите [Linux SysAdmin: Permissions & Process Management Cheatsheet](/cheatsheets/linux-sysadmin-permissions/).
