---
title: "수정: Cannot connect to the Docker daemon at unix:///var/run/docker.sock"
description: "'Cannot connect to the Docker daemon' 오류를 몇 초 만에 해결하세요. 서비스 문제인지 권한 문제인지 확인하고 영구적으로 수정하는 방법을 알아보세요."
date: 2026-02-11
tags: ["docker", "debug", "linux", "devops"]
keywords: ["cannot connect to the docker daemon", "docker daemon not running", "docker.sock permission denied", "var run docker.sock", "is the docker daemon running", "docker service start", "docker permission denied", "docker socket error", "sudo docker fix", "docker usermod group"]
draft: false
schema_json: >
  {
    "@context": "https://schema.org",
    "@type": "TechArticle",
    "name": "수정: Cannot connect to the Docker daemon at unix:///var/run/docker.sock",
    "description": "Linux에서 Docker 데몬 연결 오류를 단계별로 수정하는 가이드.",
    "proficiencyLevel": "Beginner",
    "inLanguage": "ko"
  }
---

## 오류 내용

Docker 명령어를 실행하면 다음과 같은 오류가 나타납니다:

```
Cannot connect to the Docker daemon at unix:///var/run/docker.sock. Is the docker daemon running?
```

또는 변형:

```
Got permission denied while trying to connect to the Docker daemon socket at unix:///var/run/docker.sock
```

이것은 Linux에서 가장 흔한 Docker 오류 중 하나입니다. 셸이 Docker 엔진과 통신할 수 없다는 의미입니다. 원인은 항상 두 가지 중 하나입니다: Docker 서비스가 실행되고 있지 않거나, 사용자에게 Docker 소켓에 대한 접근 권한이 없는 것입니다.

---

## 빠른 수정

### 1. Docker 서비스 시작

데몬이 단순히 실행되고 있지 않을 수 있습니다. 시작하세요:

```bash
# Start Docker now
sudo systemctl start docker

# Enable Docker to start on boot
sudo systemctl enable docker

# Verify it's running
sudo systemctl status docker
```

`status`가 `active (running)`을 표시하면 서비스가 실행 중입니다. Docker 명령어를 다시 시도하세요.

### 2. 사용자 권한 수정

서비스가 실행 중인데도 "permission denied"가 나타나면, 사용자가 `docker` 그룹에 속해 있지 않은 것입니다:

```bash
# Add your user to the docker group
sudo usermod -aG docker $USER

# Apply the new group membership (or log out and back in)
newgrp docker

# Verify you're in the group
groups
```

이 작업 후에는 `sudo` 없이 `docker ps`를 실행할 수 있어야 합니다.

---

## 설명

Docker는 Unix 소켓(`/var/run/docker.sock`)을 사용하여 CLI 클라이언트와 Docker 데몬(백그라운드 서비스) 간에 통신합니다. 이것이 작동하려면 두 가지 조건이 충족되어야 합니다:

**1. Docker 데몬이 실행 중이어야 합니다.** systemd 서비스 `docker.service`가 데몬을 관리합니다. 머신이 방금 부팅되었고 Docker가 시작 시 활성화되지 않았거나, 서비스가 충돌한 경우, 소켓 파일이 존재하지 않거나 연결을 수락하지 않습니다.

**2. 사용자가 소켓에 접근할 수 있어야 합니다.** 기본적으로 Docker 소켓은 `root:docker` 소유이며 권한은 `srw-rw----`입니다. 이는 root와 `docker` 그룹의 구성원만 읽기/쓰기할 수 있음을 의미합니다. 사용자가 `docker` 그룹에 속해 있지 않으면 모든 명령에 `sudo`가 필요합니다.

### 어떤 문제인가요?

```bash
# Check if the service is running
systemctl is-active docker

# Check socket permissions
ls -la /var/run/docker.sock

# Check if your user is in the docker group
groups $USER
```

`systemctl is-active`가 `inactive`를 반환하면 → **서비스 문제**입니다 (수정 #1).
서비스가 `active`인데 permission denied가 나타나면 → **권한 문제**입니다 (수정 #2).

---

## 흔한 실수

- **Snap으로 설치한 Docker**: 공식 저장소 대신 Snap으로 Docker를 설치한 경우, 소켓 경로와 서비스 이름이 다를 수 있습니다. Snap 버전을 제거하고 공식 Docker CE 패키지를 사용하세요.
- **Windows의 WSL2**: Docker 데몬은 WSL2에서 네이티브로 실행되지 않습니다. Docker Desktop for Windows가 실행 중이어야 하거나, WSL2 배포판 내에서 데몬을 수동으로 설치하고 시작해야 합니다.
- **Mac/Linux의 Docker Desktop**: Docker Desktop을 사용하는 경우, 데몬은 systemd가 아닌 Desktop 앱에서 관리됩니다. Docker Desktop이 열려 있고 실행 중인지 확인하세요.

---

## 관련 리소스

이 오류가 다시 발생하지 않도록 하세요. 완전한 [Docker Captain's Log Cheatsheet](/cheatsheets/docker-container-commands/)를 북마크하세요 — 사용자 권한, 서비스 관리 및 프로덕션에서 필요한 모든 `docker` 명령어를 다루고 있습니다.

Linux 서비스와 사용자를 관리해야 하나요? [Linux SysAdmin: Permissions & Process Management Cheatsheet](/cheatsheets/linux-sysadmin-permissions/)를 참고하세요.
