---
title: "SOLUZIONE: Cannot connect to the Docker daemon at unix:///var/run/docker.sock"
description: "Risolvi l'errore 'Cannot connect to the Docker daemon' in pochi secondi. Scopri se si tratta di un problema del servizio o dei permessi e risolvilo definitivamente."
date: 2026-02-11
tags: ["docker", "debug", "linux", "devops"]
keywords: ["cannot connect to the docker daemon", "docker daemon not running", "docker.sock permission denied", "var run docker.sock", "is the docker daemon running", "docker service start", "docker permission denied", "docker socket error", "sudo docker fix", "docker usermod group"]
draft: false
schema_json: >
  {
    "@context": "https://schema.org",
    "@type": "TechArticle",
    "name": "SOLUZIONE: Cannot connect to the Docker daemon at unix:///var/run/docker.sock",
    "description": "Guida passo passo per risolvere l'errore di connessione al Docker daemon su Linux.",
    "proficiencyLevel": "Beginner",
    "inLanguage": "it"
  }
---

## L'Errore

Esegui un comando Docker e ti compare questo messaggio:

```
Cannot connect to the Docker daemon at unix:///var/run/docker.sock. Is the docker daemon running?
```

Oppure una variante:

```
Got permission denied while trying to connect to the Docker daemon socket at unix:///var/run/docker.sock
```

Questo è uno degli errori Docker più comuni su Linux. Significa che la tua shell non riesce a comunicare con il motore Docker. La causa è sempre una di queste due: il servizio Docker non è in esecuzione oppure il tuo utente non ha i permessi per accedere al socket Docker.

---

## La Soluzione Rapida

### 1. Avvia il servizio Docker

Il daemon potrebbe semplicemente non essere in esecuzione. Avvialo:

```bash
# Start Docker now
sudo systemctl start docker

# Enable Docker to start on boot
sudo systemctl enable docker

# Verify it's running
sudo systemctl status docker
```

Se `status` mostra `active (running)`, il servizio è attivo. Riprova il tuo comando Docker.

### 2. Correggi i permessi utente

Se il servizio è in esecuzione ma ricevi ancora "permission denied", il tuo utente non è nel gruppo `docker`:

```bash
# Add your user to the docker group
sudo usermod -aG docker $USER

# Apply the new group membership (or log out and back in)
newgrp docker

# Verify you're in the group
groups
```

Dopo questa operazione, dovresti poter eseguire `docker ps` senza `sudo`.

---

## La Spiegazione

Docker utilizza un socket Unix (`/var/run/docker.sock`) per comunicare tra il client CLI e il daemon Docker (il servizio in background). Affinché funzioni, devono essere vere due condizioni:

**1. Il daemon Docker deve essere in esecuzione.** Il servizio systemd `docker.service` gestisce il daemon. Se la macchina è stata appena avviata e Docker non è abilitato all'avvio, oppure se il servizio si è arrestato in modo anomalo, il file socket non esiste o non accetta connessioni.

**2. Il tuo utente deve avere accesso al socket.** Per impostazione predefinita, il socket Docker è di proprietà di `root:docker` con permessi `srw-rw----`. Questo significa che solo root e i membri del gruppo `docker` possono leggere/scrivere sul socket. Se il tuo utente non è nel gruppo `docker`, ogni comando richiede `sudo`.

### Come capire qual è il problema?

```bash
# Check if the service is running
systemctl is-active docker

# Check socket permissions
ls -la /var/run/docker.sock

# Check if your user is in the docker group
groups $USER
```

Se `systemctl is-active` restituisce `inactive` → si tratta di un **problema del servizio** (Soluzione #1).
Se il servizio è `active` ma ricevi permission denied → si tratta di un **problema di permessi** (Soluzione #2).

---

## Errori Comuni

- **Docker installato via Snap**: Se hai installato Docker tramite Snap invece del repository ufficiale, il percorso del socket e il nome del servizio potrebbero essere diversi. Disinstalla la versione Snap e usa i pacchetti ufficiali Docker CE.
- **WSL2 su Windows**: Il daemon Docker non funziona nativamente in WSL2. Hai bisogno di Docker Desktop per Windows in esecuzione, oppure devi installare e avviare il daemon manualmente all'interno della tua distribuzione WSL2.
- **Docker Desktop su Mac/Linux**: Se stai usando Docker Desktop, il daemon è gestito dall'applicazione Desktop, non da systemd. Assicurati che Docker Desktop sia aperto e in esecuzione.

---

## Risorse Correlate

Evita che questo errore si ripresenti. Salva nei preferiti il nostro [Docker Captain's Log Cheatsheet](/cheatsheets/docker-container-commands/) completo — copre i permessi utente, la gestione dei servizi e tutti i comandi `docker` necessari in produzione.

Hai bisogno di gestire servizi e utenti Linux? Consulta il [Linux SysAdmin: Permissions & Process Management Cheatsheet](/cheatsheets/linux-sysadmin-permissions/).
