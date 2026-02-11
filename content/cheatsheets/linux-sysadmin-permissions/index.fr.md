---
title: "Linux SysAdmin : Permissions de Fichiers, Utilisateurs et Gestion des Processus"
description: "Commandes essentielles d'administration système Linux couvrant chmod, chown, gestion des utilisateurs, services systemd et contrôle des processus. La référence quotidienne pour tout sysadmin et ingénieur DevOps."
date: 2026-02-10
tags: ["linux", "cheatsheet", "sysadmin", "permissions", "devops"]
keywords: ["calculateur chmod", "exemples chown", "linux tuer processus", "gestion utilisateurs linux", "commandes systemd", "permissions fichiers linux", "cheatsheet sysadmin linux", "chmod 755 expliqué", "groupes utilisateurs linux", "systemctl restart service"]
draft: false
schema_json: >
  {
    "@context": "https://schema.org",
    "@type": "TechArticle",
    "name": "Linux SysAdmin : Permissions de Fichiers, Utilisateurs et Gestion des Processus",
    "description": "Commandes essentielles d'administration système Linux couvrant les permissions de fichiers, la gestion des utilisateurs, les services systemd et le contrôle des processus.",
    "proficiencyLevel": "Intermediate",
    "inLanguage": "fr"
  }
---

## Initialisation du Système

Les permissions de fichiers Linux sont la première ligne de défense de tout système. Une permission mal configurée peut exposer des données sensibles à des utilisateurs non autorisés, ou empêcher des services légitimes d'accéder aux fichiers dont ils ont besoin. Au-delà des permissions, la gestion des utilisateurs, des groupes, des services et des processus est le quotidien de tout administrateur système. Ce manuel de terrain couvre les commandes que vous utiliserez chaque jour — de la définition des permissions correctes sur la racine documentaire d'un serveur web à l'élimination d'un processus incontrôlable qui consomme toute la mémoire disponible. Chaque commande est expliquée avec des exemples pratiques pour des scénarios réels.

Ces commandes nécessitent un accès root ou sudo pour la plupart des opérations. Exécuter avec précaution.

---

## Permissions de Fichiers

Linux utilise un modèle de permissions à trois niveaux : **Propriétaire**, **Groupe** et **Autres**. Chaque niveau peut avoir des permissions de **Lecture (r=4)**, **Écriture (w=2)** et **Exécution (x=1)**. Comprendre ce modèle — et la notation numérique (octale) qui le représente — est essentiel pour sécuriser les fichiers, répertoires, scripts et données d'applications. Les permissions mal configurées sont l'une des vulnérabilités de sécurité les plus courantes sur les serveurs de production.

### Comprendre la notation des permissions

```bash
# Permission structure: [type][owner][group][others]
# Example: -rwxr-xr-- means:
#   - : regular file (d for directory)
#   rwx : owner can read, write, execute (4+2+1 = 7)
#   r-x : group can read and execute (4+0+1 = 5)
#   r-- : others can only read (4+0+0 = 4)
# Numeric notation: 754

# View permissions for files in a directory
ls -la /var/www/

# View permissions for a specific file
ls -l /etc/passwd
```

### chmod — Modifier les permissions des fichiers

```bash
# Set permissions using numeric (octal) notation
chmod 755 script.sh        # rwxr-xr-x (owner: full, group/others: read+execute)
chmod 644 config.yaml      # rw-r--r-- (owner: read+write, group/others: read)
chmod 600 id_rsa           # rw------- (owner only: read+write — SSH private keys)
chmod 700 /root            # rwx------ (owner only: full access)
chmod 777 /tmp/shared      # rwxrwxrwx (everyone: full access — avoid in production)

# Set permissions using symbolic notation
chmod u+x script.sh        # Add execute permission for owner
chmod g-w config.yaml      # Remove write permission for group
chmod o-rwx secret.key     # Remove all permissions for others
chmod a+r public.html      # Add read permission for all (a = all)

# Apply permissions recursively to a directory
chmod -R 755 /var/www/html/

# Set the setuid bit (run as file owner)
chmod u+s /usr/bin/myapp

# Set the setgid bit (new files inherit group)
chmod g+s /shared/team/

# Set the sticky bit (only owner can delete their files)
chmod +t /tmp/
```

### chown — Modifier la propriété des fichiers

```bash
# Change owner of a file
chown www-data index.html

# Change owner and group
chown www-data:www-data /var/www/html/

# Change only the group
chown :developers project/

# Change ownership recursively
chown -R deploy:deploy /opt/myapp/

# View current ownership
ls -la /var/www/
```

### Référence des permissions spéciales

```bash
# Common permission patterns for production:
# 755 — Directories, executable scripts
# 644 — Configuration files, static content
# 600 — Private keys, credentials, .env files
# 700 — Home directories, sensitive scripts
# 775 — Shared directories (with setgid for group)
# 440 — Sudoers files (/etc/sudoers.d/)

# Find files with insecure permissions (world-writable)
find / -perm -o+w -type f 2>/dev/null

# Find all SUID binaries (security audit)
find / -perm -4000 -type f 2>/dev/null

# Find all SGID binaries
find / -perm -2000 -type f 2>/dev/null
```

---

## Gestion des Utilisateurs

La gestion des utilisateurs et des groupes contrôle qui peut accéder au système et ce qu'il peut faire. Chaque processus s'exécute en tant qu'utilisateur, chaque fichier appartient à un utilisateur, et le contrôle d'accès est appliqué en fonction de l'identité de l'utilisateur. Gérer correctement les utilisateurs — les créer avec des privilèges minimaux, les affecter aux groupes appropriés et les désactiver lorsqu'ils ne sont plus nécessaires — est fondamental pour la sécurité du système.

### Créer et gérer les utilisateurs

```bash
# Create a new user with a home directory
useradd -m -s /bin/bash newuser

# Create a user with a specific UID and group
useradd -m -u 1001 -g developers -s /bin/bash deploy

# Set or change a user's password
passwd newuser

# Modify user properties (change shell)
usermod -s /bin/zsh existinguser

# Add a user to a supplementary group (without removing existing groups)
usermod -aG sudo newuser
usermod -aG docker deploy

# Lock a user account (disable login)
usermod -L compromised-user

# Unlock a user account
usermod -U restored-user

# Delete a user (keep home directory)
userdel olduser

# Delete a user and their home directory
userdel -r olduser
```

### Gérer les groupes

```bash
# Create a new group
groupadd developers

# Add a user to a group
gpasswd -a newuser developers

# Remove a user from a group
gpasswd -d newuser developers

# List all groups a user belongs to
groups newuser

# List all groups on the system
cat /etc/group

# Delete a group
groupdel old-group
```

### Configuration sudo

```bash
# Edit the sudoers file safely
visudo

# Grant a user full sudo access (add to sudoers)
echo "deploy ALL=(ALL) NOPASSWD: ALL" | sudo tee /etc/sudoers.d/deploy

# Grant a user sudo for specific commands only
echo "backup ALL=(ALL) NOPASSWD: /usr/bin/rsync, /usr/bin/tar" | sudo tee /etc/sudoers.d/backup

# Check current sudo privileges
sudo -l

# View who is currently logged in
who
w
```

---

## Services Systemd

Systemd est le système d'initialisation et le gestionnaire de services pour la plupart des distributions Linux modernes. Il contrôle quels services démarrent au boot, gère leur cycle de vie, gère les dépendances entre les services et fournit la journalisation via journald. Que vous exécutiez un serveur web, une base de données ou un démon d'application personnalisé, systemd est la manière dont vous le gérez en production.

### Gestion des services

```bash
# Start a service
sudo systemctl start nginx

# Stop a service
sudo systemctl stop nginx

# Restart a service
sudo systemctl restart nginx

# Reload configuration without restarting
sudo systemctl reload nginx

# View service status
systemctl status nginx

# Enable a service to start at boot
sudo systemctl enable nginx

# Disable a service from starting at boot
sudo systemctl disable nginx

# Check if a service is enabled
systemctl is-enabled nginx

# Check if a service is active
systemctl is-active nginx

# List all running services
systemctl list-units --type=service --state=running

# List all failed services
systemctl list-units --type=service --state=failed
```

### Logs du journal

```bash
# View logs for a specific service
journalctl -u nginx

# Follow logs in real-time
journalctl -u nginx -f

# View logs since last boot
journalctl -b

# View logs from the last hour
journalctl --since "1 hour ago"

# View logs between specific times
journalctl --since "2026-02-10 08:00" --until "2026-02-10 12:00"

# View kernel logs
journalctl -k

# Check disk usage by journal logs
journalctl --disk-usage

# Clean old journal logs (keep last 500MB)
sudo journalctl --vacuum-size=500M
```

### Créer un service personnalisé

```bash
# Create a service file for a custom application
sudo tee /etc/systemd/system/myapp.service << 'EOF'
[Unit]
Description=My Application
After=network.target

[Service]
Type=simple
User=deploy
WorkingDirectory=/opt/myapp
ExecStart=/opt/myapp/bin/server
Restart=always
RestartSec=5

[Install]
WantedBy=multi-user.target
EOF

# Reload systemd after creating/modifying a service file
sudo systemctl daemon-reload

# Start and enable the new service
sudo systemctl enable --now myapp
```

---

## Contrôle des Processus

Les processus sont les instances en cours d'exécution des programmes sur votre système. Les surveiller et les contrôler est essentiel pour la stabilité du système — un processus incontrôlable peut consommer toute la CPU ou la mémoire, un processus zombie peut remplir la table des processus, et un service qui ne répond pas doit être identifié et redémarré. Ces commandes vous donnent la visibilité et le contrôle pour gérer les processus efficacement.

### Surveiller les processus

```bash
# List all running processes
ps aux

# List processes in a tree format (show parent/child relationships)
ps auxf

# Interactive process monitor
top

# Enhanced interactive monitor (better UI)
htop

# Show top processes sorted by memory usage
ps aux --sort=-%mem | head -20

# Show top processes sorted by CPU usage
ps aux --sort=-%cpu | head -20

# Find processes by name
pgrep -la nginx

# Find the PID of a specific process
pidof nginx
```

### Terminer les processus

```bash
# Send SIGTERM (graceful shutdown, signal 15)
kill <PID>

# Send SIGKILL (force kill, signal 9)
kill -9 <PID>

# Kill all processes by name
killall nginx

# Kill processes matching a pattern
pkill -f "python server.py"

# Send SIGHUP (reload configuration)
kill -HUP <PID>
```

### Surveillance des ressources

```bash
# Show memory usage summary
free -h

# Show disk usage
df -h

# Show disk usage for a specific directory
du -sh /var/log/

# Show top 10 largest directories
du -h /var/ --max-depth=1 | sort -rh | head -10

# Monitor disk I/O
iostat -x 1

# Monitor network connections
ss -tuln

# Show active network connections with process names
ss -tulnp

# Show system uptime and load average
uptime
```
