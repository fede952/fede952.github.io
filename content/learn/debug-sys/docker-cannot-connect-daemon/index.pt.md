---
title: "CORREÇÃO: Cannot connect to the Docker daemon at unix:///var/run/docker.sock"
description: "Resolva o erro 'Cannot connect to the Docker daemon' em segundos. Descubra se é um problema de serviço ou de permissões e corrija-o permanentemente."
date: 2026-02-11
tags: ["docker", "debug", "linux", "devops"]
keywords: ["cannot connect to the docker daemon", "docker daemon not running", "docker.sock permission denied", "var run docker.sock", "is the docker daemon running", "docker service start", "docker permission denied", "docker socket error", "sudo docker fix", "docker usermod group"]
draft: false
schema_json: >
  {
    "@context": "https://schema.org",
    "@type": "TechArticle",
    "name": "CORREÇÃO: Cannot connect to the Docker daemon at unix:///var/run/docker.sock",
    "description": "Correção passo a passo para o erro de conexão ao Docker daemon no Linux.",
    "proficiencyLevel": "Beginner",
    "inLanguage": "pt"
  }
---

## O Erro

Você executa um comando Docker e recebe isto:

```
Cannot connect to the Docker daemon at unix:///var/run/docker.sock. Is the docker daemon running?
```

Ou uma variação:

```
Got permission denied while trying to connect to the Docker daemon socket at unix:///var/run/docker.sock
```

Este é um dos erros Docker mais comuns no Linux. Significa que seu shell não consegue se comunicar com o motor Docker. A causa é sempre uma de duas: o serviço Docker não está em execução ou seu usuário não tem permissão para acessar o socket Docker.

---

## A Correção Rápida

### 1. Inicie o serviço Docker

O daemon pode simplesmente não estar em execução. Inicie-o:

```bash
# Start Docker now
sudo systemctl start docker

# Enable Docker to start on boot
sudo systemctl enable docker

# Verify it's running
sudo systemctl status docker
```

Se `status` mostrar `active (running)`, o serviço está ativo. Tente seu comando Docker novamente.

### 2. Corrija as permissões do usuário

Se o serviço está em execução mas você ainda recebe "permission denied", seu usuário não está no grupo `docker`:

```bash
# Add your user to the docker group
sudo usermod -aG docker $USER

# Apply the new group membership (or log out and back in)
newgrp docker

# Verify you're in the group
groups
```

Após isso, você deverá conseguir executar `docker ps` sem `sudo`.

---

## A Explicação

O Docker usa um socket Unix (`/var/run/docker.sock`) para comunicação entre o cliente CLI e o daemon Docker (o serviço em segundo plano). Duas condições devem ser verdadeiras para que isso funcione:

**1. O daemon Docker deve estar em execução.** O serviço systemd `docker.service` gerencia o daemon. Se a máquina acabou de ser iniciada e o Docker não está habilitado na inicialização, ou se o serviço travou, o arquivo do socket não existe ou não está aceitando conexões.

**2. Seu usuário deve ter acesso ao socket.** Por padrão, o socket Docker pertence a `root:docker` com permissões `srw-rw----`. Isso significa que apenas root e membros do grupo `docker` podem ler/escrever nele. Se seu usuário não está no grupo `docker`, cada comando requer `sudo`.

### Qual é o problema?

```bash
# Check if the service is running
systemctl is-active docker

# Check socket permissions
ls -la /var/run/docker.sock

# Check if your user is in the docker group
groups $USER
```

Se `systemctl is-active` retorna `inactive` → é um **problema de serviço** (Correção #1).
Se o serviço está `active` mas você recebe permission denied → é um **problema de permissões** (Correção #2).

---

## Armadilhas Comuns

- **Docker instalado via Snap**: Se você instalou o Docker via Snap em vez do repositório oficial, o caminho do socket e o nome do serviço podem ser diferentes. Desinstale a versão Snap e use os pacotes oficiais do Docker CE.
- **WSL2 no Windows**: O daemon Docker não funciona nativamente no WSL2. Você precisa do Docker Desktop para Windows em execução, ou deve instalar e iniciar o daemon manualmente dentro da sua distribuição WSL2.
- **Docker Desktop no Mac/Linux**: Se você está usando o Docker Desktop, o daemon é gerenciado pelo aplicativo Desktop, não pelo systemd. Certifique-se de que o Docker Desktop esteja aberto e em execução.

---

## Recursos Relacionados

Evite que este erro aconteça novamente. Salve nos favoritos nosso [Docker Captain's Log Cheatsheet](/cheatsheets/docker-container-commands/) completo — ele cobre permissões de usuário, gerenciamento de serviços e todos os comandos `docker` que você precisa em produção.

Precisa gerenciar serviços e usuários Linux? Veja o [Linux SysAdmin: Permissions & Process Management Cheatsheet](/cheatsheets/linux-sysadmin-permissions/).
