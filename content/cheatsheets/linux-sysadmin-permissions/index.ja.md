---
title: "Linux SysAdmin：ファイルパーミッション、ユーザー、プロセス管理"
description: "chmod、chown、ユーザー管理、systemdサービス、プロセス制御をカバーする必須のLinuxシステム管理コマンド。すべてのシステム管理者とDevOpsエンジニアのための日常リファレンス。"
date: 2026-02-10
tags: ["linux", "cheatsheet", "sysadmin", "permissions", "devops"]
keywords: ["chmod計算機", "chownの例", "linuxプロセス終了", "linuxユーザー管理", "systemdコマンド", "linuxファイルパーミッション", "linuxシステム管理チートシート", "chmod 755の説明", "linuxユーザーグループ", "systemctl restartサービス"]
draft: false
schema_json: >
  {
    "@context": "https://schema.org",
    "@type": "TechArticle",
    "name": "Linux SysAdmin：ファイルパーミッション、ユーザー、プロセス管理",
    "description": "ファイルパーミッション、ユーザー管理、systemdサービス、プロセス制御をカバーする必須のLinuxシステム管理コマンド。",
    "proficiencyLevel": "Intermediate",
    "inLanguage": "ja"
  }
---

## システム初期化

Linuxのファイルパーミッションは、あらゆるシステムにおける最初の防衛線です。パーミッションの設定ミスは、機密データを不正なユーザーに公開したり、正当なサービスが必要なファイルにアクセスできなくなったりする可能性があります。パーミッション以外にも、ユーザー、グループ、サービス、プロセスの管理は、すべてのシステム管理者にとって日々の業務です。このフィールドマニュアルでは、Webサーバーのドキュメントルートに正しいパーミッションを設定することから、利用可能なメモリをすべて消費している暴走プロセスを終了させることまで、毎日使用するコマンドをカバーしています。各コマンドは、実際のシナリオに対する実用的な例で説明されています。

これらのコマンドは、ほとんどの操作にrootまたはsudoアクセスが必要です。慎重に実行してください。

---

## ファイルパーミッション

Linuxは3段階のパーミッションモデルを使用しています：**所有者**、**グループ**、**その他**。各段階は**読み取り（r=4）**、**書き込み（w=2）**、**実行（x=1）**のパーミッションを持つことができます。このモデル — およびそれを表す数値（8進数）表記 — を理解することは、ファイル、ディレクトリ、スクリプト、アプリケーションデータを保護するために不可欠です。パーミッションの設定ミスは、本番サーバーにおける最も一般的なセキュリティ脆弱性の一つです。

### パーミッション表記の理解

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

### chmod — ファイルパーミッションの変更

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

### chown — ファイル所有権の変更

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

### 特殊パーミッションリファレンス

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

## ユーザー管理

ユーザーとグループの管理は、誰がシステムにアクセスできるか、何ができるかを制御します。すべてのプロセスはユーザーとして実行され、すべてのファイルはユーザーが所有し、アクセス制御はユーザーのIDに基づいて適用されます。ユーザーを適切に管理すること — 最小限の権限で作成し、適切なグループに割り当て、不要になったら無効にすること — はシステムセキュリティの基本です。

### ユーザーの作成と管理

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

### グループの管理

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

### sudo設定

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

## Systemdサービス

Systemdは、ほとんどの最新Linuxディストリビューションの初期化システムおよびサービスマネージャーです。起動時にどのサービスを開始するかを制御し、そのライフサイクルを管理し、サービス間の依存関係を処理し、journaldを通じてログを提供します。Webサーバー、データベース、カスタムアプリケーションデーモンのいずれを実行する場合でも、本番環境での管理方法はsystemdです。

### サービス管理

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

### ジャーナルログ

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

### カスタムサービスの作成

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

## プロセス制御

プロセスは、システム上で実行されているプログラムのインスタンスです。それらを監視し制御することは、システムの安定性にとって不可欠です — 暴走プロセスはすべてのCPUやメモリを消費し、ゾンビプロセスはプロセステーブルを埋め尽くし、応答しないサービスは特定して再起動する必要があります。これらのコマンドは、プロセスを効果的に管理するための可視性と制御を提供します。

### プロセスの監視

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

### プロセスの終了

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

### リソース監視

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
