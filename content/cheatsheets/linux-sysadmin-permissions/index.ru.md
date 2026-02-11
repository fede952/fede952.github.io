---
title: "Linux SysAdmin: Права доступа к файлам, управление пользователями и процессами"
description: "Основные команды системного администрирования Linux, охватывающие chmod, chown, управление пользователями, сервисы systemd и контроль процессов. Ежедневный справочник для каждого сисадмина и DevOps-инженера."
date: 2026-02-10
tags: ["linux", "cheatsheet", "sysadmin", "permissions", "devops"]
keywords: ["калькулятор chmod", "примеры chown", "linux завершить процесс", "управление пользователями linux", "команды systemd", "права доступа файлов linux", "шпаргалка сисадмин linux", "chmod 755 объяснение", "группы пользователей linux", "systemctl restart сервис"]
draft: false
schema_json: >
  {
    "@context": "https://schema.org",
    "@type": "TechArticle",
    "name": "Linux SysAdmin: Права доступа к файлам, управление пользователями и процессами",
    "description": "Основные команды системного администрирования Linux, охватывающие права доступа к файлам, управление пользователями, сервисы systemd и контроль процессов.",
    "proficiencyLevel": "Intermediate",
    "inLanguage": "ru"
  }
---

## Инициализация системы

Права доступа к файлам в Linux — это первая линия обороны любой системы. Неправильно настроенное разрешение может раскрыть конфиденциальные данные неавторизованным пользователям или заблокировать доступ легитимных сервисов к необходимым файлам. Помимо прав доступа, управление пользователями, группами, сервисами и процессами — это повседневная работа любого системного администратора. Это полевое руководство охватывает команды, которые вы будете использовать каждый день — от установки правильных прав на корневую директорию документов веб-сервера до завершения неуправляемого процесса, потребляющего всю доступную память. Каждая команда объясняется с практическими примерами для реальных сценариев.

Эти команды требуют доступа root или sudo для большинства операций. Выполняйте с осторожностью.

---

## Права доступа к файлам

Linux использует трёхуровневую модель прав доступа: **Владелец**, **Группа** и **Остальные**. Каждый уровень может иметь права на **Чтение (r=4)**, **Запись (w=2)** и **Исполнение (x=1)**. Понимание этой модели — и числовой (восьмеричной) нотации, которая её представляет — необходимо для защиты файлов, директорий, скриптов и данных приложений. Неправильно настроенные права доступа — одна из самых распространённых уязвимостей безопасности на продуктивных серверах.

### Понимание нотации прав доступа

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

### chmod — Изменение прав доступа к файлам

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

### chown — Изменение владельца файлов

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

### Справочник по специальным правам доступа

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

## Управление пользователями

Управление пользователями и группами определяет, кто может получить доступ к системе и что может делать. Каждый процесс выполняется от имени пользователя, каждый файл принадлежит пользователю, а контроль доступа осуществляется на основе идентификации пользователя. Правильное управление пользователями — создание их с минимальными привилегиями, назначение в соответствующие группы и отключение, когда они больше не нужны — является основой безопасности системы.

### Создание и управление пользователями

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

### Управление группами

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

### Настройка sudo

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

## Сервисы Systemd

Systemd — это система инициализации и менеджер сервисов для большинства современных дистрибутивов Linux. Он контролирует, какие сервисы запускаются при загрузке, управляет их жизненным циклом, обрабатывает зависимости между сервисами и обеспечивает логирование через journald. Независимо от того, запускаете ли вы веб-сервер, базу данных или пользовательский демон приложения, systemd — это способ управления ими в продуктивной среде.

### Управление сервисами

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

### Журналы логов

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

### Создание пользовательского сервиса

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

## Контроль процессов

Процессы — это работающие экземпляры программ в вашей системе. Мониторинг и управление ими необходимы для стабильности системы — неуправляемый процесс может потребить всю CPU или память, процесс-зомби может заполнить таблицу процессов, а не отвечающий сервис нужно идентифицировать и перезапустить. Эти команды дают вам видимость и контроль для эффективного управления процессами.

### Мониторинг процессов

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

### Завершение процессов

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

### Мониторинг ресурсов

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
