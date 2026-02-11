---
title: "Linux SysAdmin: Permessi dei File, Utenti e Gestione dei Processi"
description: "Comandi essenziali per l'amministrazione di sistema Linux che coprono chmod, chown, gestione utenti, servizi systemd e controllo dei processi. Il riferimento quotidiano per ogni sysadmin e ingegnere DevOps."
date: 2026-02-10
tags: ["linux", "cheatsheet", "sysadmin", "permissions", "devops"]
keywords: ["calcolatore chmod", "esempi chown", "linux kill processo", "gestione utenti linux", "comandi systemd", "permessi file linux", "cheatsheet sysadmin linux", "chmod 755 spiegato", "gruppi utenti linux", "systemctl restart servizio"]
draft: false
schema_json: >
  {
    "@context": "https://schema.org",
    "@type": "TechArticle",
    "name": "Linux SysAdmin: Permessi dei File, Utenti e Gestione dei Processi",
    "description": "Comandi essenziali per l'amministrazione di sistema Linux che coprono permessi dei file, gestione utenti, servizi systemd e controllo dei processi.",
    "proficiencyLevel": "Intermediate",
    "inLanguage": "it"
  }
---

## Inizializzazione del Sistema

I permessi dei file Linux sono la prima linea di difesa in qualsiasi sistema. Un permesso configurato in modo errato può esporre dati sensibili a utenti non autorizzati, o bloccare l'accesso ai file necessari per i servizi legittimi. Oltre ai permessi, la gestione di utenti, gruppi, servizi e processi è il pane quotidiano di qualsiasi amministratore di sistema. Questo manuale operativo copre i comandi che userai ogni giorno — dall'impostazione dei permessi corretti sulla document root di un server web all'eliminazione di un processo fuori controllo che sta consumando tutta la memoria disponibile. Ogni comando è spiegato con esempi pratici per scenari reali.

Questi comandi richiedono accesso root o sudo per la maggior parte delle operazioni. Eseguire con cautela.

---

## Permessi dei File

Linux utilizza un modello di permessi a tre livelli: **Proprietario**, **Gruppo** e **Altri**. Ogni livello può avere permessi di **Lettura (r=4)**, **Scrittura (w=2)** e **Esecuzione (x=1)**. Comprendere questo modello — e la notazione numerica (ottale) che lo rappresenta — è essenziale per proteggere file, directory, script e dati delle applicazioni. I permessi configurati in modo errato sono una delle vulnerabilità di sicurezza più comuni nei server di produzione.

### Comprendere la notazione dei permessi

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

### chmod — Modificare i permessi dei file

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

### chown — Modificare la proprietà dei file

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

### Riferimento permessi speciali

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

## Gestione Utenti

La gestione di utenti e gruppi controlla chi può accedere al sistema e cosa può fare. Ogni processo viene eseguito come un utente, ogni file è di proprietà di un utente, e il controllo degli accessi viene applicato in base all'identità dell'utente. Gestire correttamente gli utenti — crearli con privilegi minimi, assegnarli ai gruppi appropriati e disabilitarli quando non sono più necessari — è fondamentale per la sicurezza del sistema.

### Creare e gestire gli utenti

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

### Gestire i gruppi

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

### Configurazione sudo

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

## Servizi Systemd

Systemd è il sistema di init e il gestore dei servizi per la maggior parte delle distribuzioni Linux moderne. Controlla quali servizi si avviano all'accensione, gestisce il loro ciclo di vita, gestisce le dipendenze tra servizi e fornisce il logging tramite journald. Che tu stia eseguendo un server web, un database o un demone applicativo personalizzato, systemd è il modo in cui lo gestisci in produzione.

### Gestione dei servizi

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

### Log del journal

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

### Creare un servizio personalizzato

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

## Controllo dei Processi

I processi sono le istanze in esecuzione dei programmi sul tuo sistema. Monitorarli e controllarli è essenziale per la stabilità del sistema — un processo fuori controllo può consumare tutta la CPU o la memoria, un processo zombie può riempire la tabella dei processi, e un servizio che non risponde deve essere identificato e riavviato. Questi comandi ti danno la visibilità e il controllo per gestire i processi in modo efficace.

### Monitorare i processi

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

### Terminare i processi

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

### Monitoraggio delle risorse

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
