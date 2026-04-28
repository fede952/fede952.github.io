---
title: "CORRECTIF: Cannot connect to the Docker daemon at unix:///var/run/docker.sock"
description: "Résolvez l'erreur 'Cannot connect to the Docker daemon' en quelques secondes. Déterminez s'il s'agit d'un problème de service ou de permissions et corrigez-le définitivement."
date: 2026-02-11
tags: ["docker", "debug", "linux", "devops"]
keywords: ["cannot connect to the docker daemon", "docker daemon not running", "docker.sock permission denied", "var run docker.sock", "is the docker daemon running", "docker service start", "docker permission denied", "docker socket error", "sudo docker fix", "docker usermod group"]
draft: false
schema_json: >
  {
    "@context": "https://schema.org",
    "@type": "TechArticle",
    "name": "CORRECTIF: Cannot connect to the Docker daemon at unix:///var/run/docker.sock",
    "description": "Correction étape par étape de l'erreur de connexion au Docker daemon sous Linux.",
    "proficiencyLevel": "Beginner",
    "inLanguage": "fr"
  }
---

## L'Erreur

Vous exécutez une commande Docker et vous obtenez ceci :

```
Cannot connect to the Docker daemon at unix:///var/run/docker.sock. Is the docker daemon running?
```

Ou une variante :

```
Got permission denied while trying to connect to the Docker daemon socket at unix:///var/run/docker.sock
```

C'est l'une des erreurs Docker les plus courantes sous Linux. Cela signifie que votre shell ne peut pas communiquer avec le moteur Docker. La cause est toujours l'une des deux suivantes : le service Docker n'est pas en cours d'exécution ou votre utilisateur n'a pas les permissions pour accéder au socket Docker.

---

## La Solution Rapide

### 1. Démarrez le service Docker

Le daemon n'est peut-être tout simplement pas en cours d'exécution. Démarrez-le :

```bash
# Start Docker now
sudo systemctl start docker

# Enable Docker to start on boot
sudo systemctl enable docker

# Verify it's running
sudo systemctl status docker
```

Si `status` affiche `active (running)`, le service est actif. Réessayez votre commande Docker.

### 2. Corrigez les permissions utilisateur

Si le service est en cours d'exécution mais que vous obtenez toujours "permission denied", votre utilisateur n'est pas dans le groupe `docker` :

```bash
# Add your user to the docker group
sudo usermod -aG docker $USER

# Apply the new group membership (or log out and back in)
newgrp docker

# Verify you're in the group
groups
```

Après cela, vous devriez pouvoir exécuter `docker ps` sans `sudo`.

---

## L'Explication

Docker utilise un socket Unix (`/var/run/docker.sock`) pour communiquer entre le client CLI et le daemon Docker (le service en arrière-plan). Deux conditions doivent être remplies pour que cela fonctionne :

**1. Le daemon Docker doit être en cours d'exécution.** Le service systemd `docker.service` gère le daemon. Si la machine vient de démarrer et que Docker n'est pas activé au démarrage, ou si le service a planté, le fichier socket n'existe pas ou n'accepte pas les connexions.

**2. Votre utilisateur doit avoir accès au socket.** Par défaut, le socket Docker appartient à `root:docker` avec les permissions `srw-rw----`. Cela signifie que seuls root et les membres du groupe `docker` peuvent lire/écrire dessus. Si votre utilisateur n'est pas dans le groupe `docker`, chaque commande nécessite `sudo`.

### Lequel est-ce ?

```bash
# Check if the service is running
systemctl is-active docker

# Check socket permissions
ls -la /var/run/docker.sock

# Check if your user is in the docker group
groups $USER
```

Si `systemctl is-active` renvoie `inactive` → c'est un **problème de service** (Correctif #1).
Si le service est `active` mais que vous obtenez permission denied → c'est un **problème de permissions** (Correctif #2).

---

## Pièges Courants

- **Docker installé via Snap** : Si vous avez installé Docker via Snap au lieu du dépôt officiel, le chemin du socket et le nom du service peuvent être différents. Désinstallez la version Snap et utilisez les paquets officiels Docker CE.
- **WSL2 sous Windows** : Le daemon Docker ne fonctionne pas nativement dans WSL2. Vous avez besoin de Docker Desktop pour Windows en cours d'exécution, ou vous devez installer et démarrer le daemon manuellement dans votre distribution WSL2.
- **Docker Desktop sur Mac/Linux** : Si vous utilisez Docker Desktop, le daemon est géré par l'application Desktop, pas par systemd. Assurez-vous que Docker Desktop est ouvert et en cours d'exécution.

---

## Ressources Associées

Empêchez cette erreur de se reproduire. Ajoutez à vos favoris notre [Docker Captain's Log Cheatsheet](/cheatsheets/docker-container-commands/) complet — il couvre les permissions utilisateur, la gestion des services et toutes les commandes `docker` dont vous avez besoin en production.

Besoin de gérer les services et les utilisateurs Linux ? Consultez le [Linux SysAdmin: Permissions & Process Management Cheatsheet](/cheatsheets/linux-sysadmin-permissions/).
