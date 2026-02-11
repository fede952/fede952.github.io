---
title: "SOLUCIÓN: Cannot connect to the Docker daemon at unix:///var/run/docker.sock"
description: "Resuelve el error 'Cannot connect to the Docker daemon' en segundos. Aprende si es un problema del servicio o de permisos y corrígelo de forma permanente."
date: 2026-02-11
tags: ["docker", "debug", "linux", "devops"]
keywords: ["cannot connect to the docker daemon", "docker daemon not running", "docker.sock permission denied", "var run docker.sock", "is the docker daemon running", "docker service start", "docker permission denied", "docker socket error", "sudo docker fix", "docker usermod group"]
draft: false
schema_json: >
  {
    "@context": "https://schema.org",
    "@type": "TechArticle",
    "name": "SOLUCIÓN: Cannot connect to the Docker daemon at unix:///var/run/docker.sock",
    "description": "Solución paso a paso para el error de conexión al Docker daemon en Linux.",
    "proficiencyLevel": "Beginner",
    "inLanguage": "es"
  }
---

## El Error

Ejecutas un comando de Docker y te aparece esto:

```
Cannot connect to the Docker daemon at unix:///var/run/docker.sock. Is the docker daemon running?
```

O una variación:

```
Got permission denied while trying to connect to the Docker daemon socket at unix:///var/run/docker.sock
```

Este es uno de los errores de Docker más comunes en Linux. Significa que tu shell no puede comunicarse con el motor de Docker. La causa siempre es una de dos: el servicio de Docker no está en ejecución o tu usuario no tiene permisos para acceder al socket de Docker.

---

## La Solución Rápida

### 1. Inicia el servicio de Docker

Es posible que el daemon simplemente no esté en ejecución. Inícialo:

```bash
# Start Docker now
sudo systemctl start docker

# Enable Docker to start on boot
sudo systemctl enable docker

# Verify it's running
sudo systemctl status docker
```

Si `status` muestra `active (running)`, el servicio está activo. Intenta tu comando de Docker de nuevo.

### 2. Corrige los permisos de usuario

Si el servicio está en ejecución pero sigues recibiendo "permission denied", tu usuario no está en el grupo `docker`:

```bash
# Add your user to the docker group
sudo usermod -aG docker $USER

# Apply the new group membership (or log out and back in)
newgrp docker

# Verify you're in the group
groups
```

Después de esto, deberías poder ejecutar `docker ps` sin `sudo`.

---

## La Explicación

Docker utiliza un socket Unix (`/var/run/docker.sock`) para comunicarse entre el cliente CLI y el daemon de Docker (el servicio en segundo plano). Para que esto funcione, deben cumplirse dos condiciones:

**1. El daemon de Docker debe estar en ejecución.** El servicio de systemd `docker.service` gestiona el daemon. Si la máquina acaba de arrancar y Docker no está habilitado en el inicio, o si el servicio se cayó, el archivo del socket no existe o no acepta conexiones.

**2. Tu usuario debe tener acceso al socket.** Por defecto, el socket de Docker pertenece a `root:docker` con permisos `srw-rw----`. Esto significa que solo root y los miembros del grupo `docker` pueden leer/escribir en él. Si tu usuario no está en el grupo `docker`, cada comando requiere `sudo`.

### ¿Cuál es el problema?

```bash
# Check if the service is running
systemctl is-active docker

# Check socket permissions
ls -la /var/run/docker.sock

# Check if your user is in the docker group
groups $USER
```

Si `systemctl is-active` devuelve `inactive` → es un **problema del servicio** (Solución #1).
Si el servicio está `active` pero recibes permission denied → es un **problema de permisos** (Solución #2).

---

## Errores Comunes

- **Docker instalado vía Snap**: Si instalaste Docker a través de Snap en lugar del repositorio oficial, la ruta del socket y el nombre del servicio pueden ser diferentes. Desinstala la versión de Snap y usa los paquetes oficiales de Docker CE.
- **WSL2 en Windows**: El daemon de Docker no se ejecuta de forma nativa en WSL2. Necesitas Docker Desktop para Windows en ejecución, o debes instalar e iniciar el daemon dentro de tu distribución WSL2 manualmente.
- **Docker Desktop en Mac/Linux**: Si estás usando Docker Desktop, el daemon es gestionado por la aplicación Desktop, no por systemd. Asegúrate de que Docker Desktop esté abierto y en ejecución.

---

## Recursos Relacionados

Evita que este error vuelva a ocurrir. Guarda en favoritos nuestro [Docker Captain's Log Cheatsheet](/cheatsheets/docker-container-commands/) completo — cubre permisos de usuario, gestión de servicios y todos los comandos `docker` que necesitas en producción.

¿Necesitas gestionar servicios y usuarios de Linux? Consulta el [Linux SysAdmin: Permissions & Process Management Cheatsheet](/cheatsheets/linux-sysadmin-permissions/).
