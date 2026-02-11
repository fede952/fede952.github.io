---
title: "Linux SysAdmin: Dateiberechtigungen, Benutzer und Prozessverwaltung"
description: "Essenzielle Linux-Systemadministrationsbefehle zu chmod, chown, Benutzerverwaltung, systemd-Diensten und Prozesskontrolle. Die tägliche Referenz für jeden Sysadmin und DevOps-Ingenieur."
date: 2026-02-10
tags: ["linux", "cheatsheet", "sysadmin", "permissions", "devops"]
keywords: ["chmod Rechner", "chown Beispiele", "Linux Prozess beenden", "Benutzerverwaltung Linux", "systemd Befehle", "Linux Dateiberechtigungen", "Linux Sysadmin Cheatsheet", "chmod 755 erklärt", "Linux Benutzergruppen", "systemctl restart Dienst"]
draft: false
schema_json: >
  {
    "@context": "https://schema.org",
    "@type": "TechArticle",
    "name": "Linux SysAdmin: Dateiberechtigungen, Benutzer und Prozessverwaltung",
    "description": "Essenzielle Linux-Sysadmin-Befehle zu Dateiberechtigungen, Benutzerverwaltung, systemd-Diensten und Prozesskontrolle.",
    "proficiencyLevel": "Intermediate",
    "inLanguage": "de"
  }
---

## Systeminitialisierung

Linux-Dateiberechtigungen sind die erste Verteidigungslinie in jedem System. Eine falsch konfigurierte Berechtigung kann sensible Daten für unbefugte Benutzer zugänglich machen oder legitime Dienste von den benötigten Dateien aussperren. Über Berechtigungen hinaus ist die Verwaltung von Benutzern, Gruppen, Diensten und Prozessen das tägliche Brot jedes Systemadministrators. Dieses Feldhandbuch behandelt die Befehle, die Sie jeden Tag verwenden werden — von der Einstellung der richtigen Berechtigungen im Dokumentenstamm eines Webservers bis zum Beenden eines außer Kontrolle geratenen Prozesses, der den gesamten verfügbaren Speicher verbraucht. Jeder Befehl wird mit praktischen Beispielen für reale Szenarien erklärt.

Diese Befehle erfordern für die meisten Operationen Root- oder Sudo-Zugriff. Mit Vorsicht ausführen.

---

## Dateiberechtigungen

Linux verwendet ein dreistufiges Berechtigungsmodell: **Eigentümer**, **Gruppe** und **Andere**. Jede Stufe kann Berechtigungen für **Lesen (r=4)**, **Schreiben (w=2)** und **Ausführen (x=1)** haben. Dieses Modell zu verstehen — und die numerische (oktale) Notation, die es darstellt — ist essenziell für die Absicherung von Dateien, Verzeichnissen, Skripten und Anwendungsdaten. Falsch konfigurierte Berechtigungen gehören zu den häufigsten Sicherheitslücken auf Produktionsservern.

### Berechtigungsnotation verstehen

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

### chmod — Dateiberechtigungen ändern

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

### chown — Dateieigentümerschaft ändern

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

### Referenz für Spezialberechtigungen

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

## Benutzerverwaltung

Die Benutzer- und Gruppenverwaltung steuert, wer auf das System zugreifen kann und was er tun darf. Jeder Prozess läuft als Benutzer, jede Datei gehört einem Benutzer, und die Zugriffskontrolle wird basierend auf der Benutzeridentität durchgesetzt. Benutzer korrekt zu verwalten — sie mit minimalen Privilegien zu erstellen, sie den entsprechenden Gruppen zuzuweisen und sie zu deaktivieren, wenn sie nicht mehr benötigt werden — ist grundlegend für die Systemsicherheit.

### Benutzer erstellen und verwalten

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

### Gruppen verwalten

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

### Sudo-Konfiguration

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

## Systemd-Dienste

Systemd ist das Init-System und der Dienstmanager für die meisten modernen Linux-Distributionen. Es steuert, welche Dienste beim Booten starten, verwaltet deren Lebenszyklus, handhabt Abhängigkeiten zwischen Diensten und bietet Protokollierung über journald. Ob Sie einen Webserver, eine Datenbank oder einen benutzerdefinierten Anwendungsdämon betreiben — systemd ist die Art und Weise, wie Sie es in der Produktion verwalten.

### Dienstverwaltung

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

### Journal-Protokolle

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

### Einen benutzerdefinierten Dienst erstellen

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

## Prozesskontrolle

Prozesse sind die laufenden Instanzen von Programmen auf Ihrem System. Sie zu überwachen und zu steuern ist essenziell für die Systemstabilität — ein außer Kontrolle geratener Prozess kann die gesamte CPU oder den Speicher verbrauchen, ein Zombie-Prozess kann die Prozesstabelle füllen, und ein nicht reagierender Dienst muss identifiziert und neu gestartet werden. Diese Befehle geben Ihnen die Sichtbarkeit und Kontrolle, um Prozesse effektiv zu verwalten.

### Prozesse überwachen

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

### Prozesse beenden

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

### Ressourcenüberwachung

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
