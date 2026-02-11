---
title: "Linux SysAdmin: Permisos de Archivos, Usuarios y Gestión de Procesos"
description: "Comandos esenciales de administración de sistemas Linux que cubren chmod, chown, gestión de usuarios, servicios systemd y control de procesos. La referencia diaria para todo sysadmin e ingeniero DevOps."
date: 2026-02-10
tags: ["linux", "cheatsheet", "sysadmin", "permissions", "devops"]
keywords: ["calculadora chmod", "ejemplos chown", "linux matar proceso", "gestión usuarios linux", "comandos systemd", "permisos archivos linux", "cheatsheet sysadmin linux", "chmod 755 explicado", "grupos usuarios linux", "systemctl restart servicio"]
draft: false
schema_json: >
  {
    "@context": "https://schema.org",
    "@type": "TechArticle",
    "name": "Linux SysAdmin: Permisos de Archivos, Usuarios y Gestión de Procesos",
    "description": "Comandos esenciales de administración de sistemas Linux que cubren permisos de archivos, gestión de usuarios, servicios systemd y control de procesos.",
    "proficiencyLevel": "Intermediate",
    "inLanguage": "es"
  }
---

## Inicio del Sistema

Los permisos de archivos en Linux son la primera línea de defensa en cualquier sistema. Un permiso mal configurado puede exponer datos sensibles a usuarios no autorizados, o bloquear el acceso de servicios legítimos a los archivos que necesitan. Más allá de los permisos, la gestión de usuarios, grupos, servicios y procesos es el pan de cada día de cualquier administrador de sistemas. Este manual de campo cubre los comandos que usarás todos los días — desde establecer los permisos correctos en el document root de un servidor web hasta eliminar un proceso descontrolado que está consumiendo toda la memoria disponible. Cada comando se explica con ejemplos prácticos para escenarios del mundo real.

Estos comandos requieren acceso root o sudo para la mayoría de las operaciones. Ejecutar con precaución.

---

## Permisos de Archivos

Linux utiliza un modelo de permisos de tres niveles: **Propietario**, **Grupo** y **Otros**. Cada nivel puede tener permisos de **Lectura (r=4)**, **Escritura (w=2)** y **Ejecución (x=1)**. Comprender este modelo — y la notación numérica (octal) que lo representa — es esencial para proteger archivos, directorios, scripts y datos de aplicaciones. Los permisos mal configurados son una de las vulnerabilidades de seguridad más comunes en servidores de producción.

### Comprender la notación de permisos

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

### chmod — Cambiar permisos de archivos

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

### chown — Cambiar la propiedad de archivos

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

### Referencia de permisos especiales

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

## Gestión de Usuarios

La gestión de usuarios y grupos controla quién puede acceder al sistema y qué puede hacer. Cada proceso se ejecuta como un usuario, cada archivo pertenece a un usuario, y el control de acceso se aplica en función de la identidad del usuario. Gestionar correctamente los usuarios — crearlos con privilegios mínimos, asignarlos a los grupos apropiados y deshabilitarlos cuando ya no sean necesarios — es fundamental para la seguridad del sistema.

### Crear y gestionar usuarios

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

### Gestionar grupos

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

### Configuración de sudo

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

## Servicios Systemd

Systemd es el sistema de inicio y gestor de servicios para la mayoría de las distribuciones Linux modernas. Controla qué servicios se inician en el arranque, gestiona su ciclo de vida, maneja las dependencias entre servicios y proporciona registro de eventos a través de journald. Ya sea que estés ejecutando un servidor web, una base de datos o un demonio de aplicación personalizado, systemd es la forma en que lo gestionas en producción.

### Gestión de servicios

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

### Logs del journal

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

### Crear un servicio personalizado

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

## Control de Procesos

Los procesos son las instancias en ejecución de los programas en tu sistema. Monitorearlos y controlarlos es esencial para la estabilidad del sistema — un proceso descontrolado puede consumir toda la CPU o la memoria, un proceso zombie puede llenar la tabla de procesos, y un servicio que no responde necesita ser identificado y reiniciado. Estos comandos te dan la visibilidad y el control para gestionar procesos de manera efectiva.

### Monitorear procesos

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

### Terminar procesos

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

### Monitoreo de recursos

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
