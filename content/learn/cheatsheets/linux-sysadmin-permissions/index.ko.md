---
title: "Linux SysAdmin: 파일 권한, 사용자 및 프로세스 관리"
description: "chmod, chown, 사용자 관리, systemd 서비스 및 프로세스 제어를 다루는 필수 Linux 시스템 관리 명령어. 모든 시스템 관리자와 DevOps 엔지니어를 위한 일일 참조 가이드."
date: 2026-02-10
tags: ["linux", "cheatsheet", "sysadmin", "permissions", "devops"]
keywords: ["chmod 계산기", "chown 예제", "linux 프로세스 종료", "linux 사용자 관리", "systemd 명령어", "linux 파일 권한", "linux 시스템관리 치트시트", "chmod 755 설명", "linux 사용자 그룹", "systemctl restart 서비스"]
draft: false
schema_json: >
  {
    "@context": "https://schema.org",
    "@type": "TechArticle",
    "name": "Linux SysAdmin: 파일 권한, 사용자 및 프로세스 관리",
    "description": "파일 권한, 사용자 관리, systemd 서비스 및 프로세스 제어를 다루는 필수 Linux 시스템 관리 명령어.",
    "proficiencyLevel": "Intermediate",
    "inLanguage": "ko"
  }
---

## 시스템 초기화

Linux 파일 권한은 모든 시스템에서 첫 번째 방어선입니다. 잘못 구성된 권한은 민감한 데이터를 인가되지 않은 사용자에게 노출시키거나, 정상적인 서비스가 필요한 파일에 접근하지 못하게 차단할 수 있습니다. 권한 외에도 사용자, 그룹, 서비스 및 프로세스를 관리하는 것은 모든 시스템 관리자의 일상 업무입니다. 이 필드 매뉴얼은 웹 서버의 문서 루트에 올바른 권한을 설정하는 것부터 사용 가능한 모든 메모리를 소비하는 폭주 프로세스를 종료하는 것까지, 매일 사용할 명령어를 다룹니다. 모든 명령어는 실제 시나리오에 대한 실용적인 예제와 함께 설명됩니다.

이 명령어들은 대부분의 작업에 root 또는 sudo 접근이 필요합니다. 주의하여 실행하십시오.

---

## 파일 권한

Linux는 3단계 권한 모델을 사용합니다: **소유자**, **그룹**, **기타**. 각 단계는 **읽기(r=4)**, **쓰기(w=2)**, **실행(x=1)** 권한을 가질 수 있습니다. 이 모델과 이를 나타내는 숫자(8진수) 표기법을 이해하는 것은 파일, 디렉토리, 스크립트 및 애플리케이션 데이터를 보호하는 데 필수적입니다. 잘못 구성된 권한은 프로덕션 서버에서 가장 흔한 보안 취약점 중 하나입니다.

### 권한 표기법 이해

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

### chmod — 파일 권한 변경

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

### chown — 파일 소유권 변경

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

### 특수 권한 참조

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

## 사용자 관리

사용자 및 그룹 관리는 시스템에 누가 접근할 수 있고 무엇을 할 수 있는지를 제어합니다. 모든 프로세스는 사용자로 실행되고, 모든 파일은 사용자가 소유하며, 접근 제어는 사용자 ID를 기반으로 적용됩니다. 사용자를 올바르게 관리하는 것 — 최소한의 권한으로 생성하고, 적절한 그룹에 할당하고, 더 이상 필요하지 않을 때 비활성화하는 것 — 은 시스템 보안의 기본입니다.

### 사용자 생성 및 관리

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

### 그룹 관리

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

### sudo 설정

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

## Systemd 서비스

Systemd는 대부분의 최신 Linux 배포판의 init 시스템이자 서비스 관리자입니다. 부팅 시 어떤 서비스가 시작되는지 제어하고, 수명 주기를 관리하며, 서비스 간 의존성을 처리하고, journald를 통해 로깅을 제공합니다. 웹 서버, 데이터베이스 또는 사용자 정의 애플리케이션 데몬을 실행하든, systemd가 프로덕션에서 관리하는 방법입니다.

### 서비스 관리

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

### 저널 로그

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

### 사용자 정의 서비스 생성

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

## 프로세스 제어

프로세스는 시스템에서 실행 중인 프로그램의 인스턴스입니다. 이를 모니터링하고 제어하는 것은 시스템 안정성에 필수적입니다 — 폭주 프로세스는 모든 CPU 또는 메모리를 소비할 수 있고, 좀비 프로세스는 프로세스 테이블을 채울 수 있으며, 응답하지 않는 서비스는 식별하고 재시작해야 합니다. 이 명령어들은 프로세스를 효과적으로 관리하기 위한 가시성과 제어를 제공합니다.

### 프로세스 모니터링

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

### 프로세스 종료

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

### 리소스 모니터링

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
