---
title: "LÖSUNG: Cannot connect to the Docker daemon at unix:///var/run/docker.sock"
description: "Beheben Sie den Fehler 'Cannot connect to the Docker daemon' in Sekunden. Erfahren Sie, ob es ein Service- oder Berechtigungsproblem ist, und beheben Sie es dauerhaft."
date: 2026-02-11
tags: ["docker", "debug", "linux", "devops"]
keywords: ["cannot connect to the docker daemon", "docker daemon not running", "docker.sock permission denied", "var run docker.sock", "is the docker daemon running", "docker service start", "docker permission denied", "docker socket error", "sudo docker fix", "docker usermod group"]
draft: false
schema_json: >
  {
    "@context": "https://schema.org",
    "@type": "TechArticle",
    "name": "LÖSUNG: Cannot connect to the Docker daemon at unix:///var/run/docker.sock",
    "description": "Schritt-für-Schritt-Lösung für den Docker-Daemon-Verbindungsfehler unter Linux.",
    "proficiencyLevel": "Beginner",
    "inLanguage": "de"
  }
---

## Der Fehler

Sie führen einen Docker-Befehl aus und erhalten Folgendes:

```
Cannot connect to the Docker daemon at unix:///var/run/docker.sock. Is the docker daemon running?
```

Oder eine Variante:

```
Got permission denied while trying to connect to the Docker daemon socket at unix:///var/run/docker.sock
```

Dies ist einer der häufigsten Docker-Fehler unter Linux. Es bedeutet, dass Ihre Shell nicht mit der Docker-Engine kommunizieren kann. Die Ursache ist immer eine von zwei Möglichkeiten: Der Docker-Dienst läuft nicht oder Ihr Benutzer hat keine Berechtigung, auf den Docker-Socket zuzugreifen.

---

## Die Schnelle Lösung

### 1. Starten Sie den Docker-Dienst

Der Daemon läuft möglicherweise einfach nicht. Starten Sie ihn:

```bash
# Start Docker now
sudo systemctl start docker

# Enable Docker to start on boot
sudo systemctl enable docker

# Verify it's running
sudo systemctl status docker
```

Wenn `status` `active (running)` anzeigt, läuft der Dienst. Versuchen Sie Ihren Docker-Befehl erneut.

### 2. Benutzerberechtigungen korrigieren

Wenn der Dienst läuft, Sie aber weiterhin "permission denied" erhalten, ist Ihr Benutzer nicht in der Gruppe `docker`:

```bash
# Add your user to the docker group
sudo usermod -aG docker $USER

# Apply the new group membership (or log out and back in)
newgrp docker

# Verify you're in the group
groups
```

Danach sollten Sie `docker ps` ohne `sudo` ausführen können.

---

## Die Erklärung

Docker verwendet einen Unix-Socket (`/var/run/docker.sock`) zur Kommunikation zwischen dem CLI-Client und dem Docker-Daemon (dem Hintergrunddienst). Damit dies funktioniert, müssen zwei Bedingungen erfüllt sein:

**1. Der Docker-Daemon muss laufen.** Der systemd-Dienst `docker.service` verwaltet den Daemon. Wenn die Maschine gerade gestartet wurde und Docker beim Start nicht aktiviert ist, oder wenn der Dienst abgestürzt ist, existiert die Socket-Datei entweder nicht oder akzeptiert keine Verbindungen.

**2. Ihr Benutzer muss Zugriff auf den Socket haben.** Standardmäßig gehört der Docker-Socket `root:docker` mit den Berechtigungen `srw-rw----`. Das bedeutet, dass nur root und Mitglieder der Gruppe `docker` darauf lesen/schreiben können. Wenn Ihr Benutzer nicht in der Gruppe `docker` ist, erfordert jeder Befehl `sudo`.

### Welches Problem liegt vor?

```bash
# Check if the service is running
systemctl is-active docker

# Check socket permissions
ls -la /var/run/docker.sock

# Check if your user is in the docker group
groups $USER
```

Wenn `systemctl is-active` `inactive` zurückgibt → es ist ein **Service-Problem** (Lösung #1).
Wenn der Dienst `active` ist, Sie aber permission denied erhalten → es ist ein **Berechtigungsproblem** (Lösung #2).

---

## Häufige Fallstricke

- **Docker über Snap installiert**: Wenn Sie Docker über Snap statt über das offizielle Repository installiert haben, können sich der Socket-Pfad und der Dienstname unterscheiden. Deinstallieren Sie die Snap-Version und verwenden Sie die offiziellen Docker-CE-Pakete.
- **WSL2 unter Windows**: Der Docker-Daemon läuft nicht nativ in WSL2. Sie benötigen Docker Desktop für Windows oder müssen den Daemon manuell in Ihrer WSL2-Distribution installieren und starten.
- **Docker Desktop auf Mac/Linux**: Wenn Sie Docker Desktop verwenden, wird der Daemon von der Desktop-App verwaltet, nicht von systemd. Stellen Sie sicher, dass Docker Desktop geöffnet und aktiv ist.

---

## Verwandte Ressourcen

Verhindern Sie, dass dieser Fehler erneut auftritt. Setzen Sie ein Lesezeichen für unser vollständiges [Docker Captain's Log Cheatsheet](/cheatsheets/docker-container-commands/) — es behandelt Benutzerberechtigungen, Dienstverwaltung und jeden `docker`-Befehl, den Sie in der Produktion benötigen.

Müssen Sie Linux-Dienste und Benutzer verwalten? Siehe das [Linux SysAdmin: Permissions & Process Management Cheatsheet](/cheatsheets/linux-sysadmin-permissions/).
