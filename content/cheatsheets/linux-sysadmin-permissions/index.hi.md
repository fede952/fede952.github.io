---
title: "Linux SysAdmin: फ़ाइल अनुमतियाँ, उपयोगकर्ता और प्रक्रिया प्रबंधन"
description: "chmod, chown, उपयोगकर्ता प्रबंधन, systemd सेवाओं और प्रक्रिया नियंत्रण को कवर करने वाले आवश्यक Linux सिस्टम प्रशासन कमांड। हर sysadmin और DevOps इंजीनियर के लिए दैनिक संदर्भ।"
date: 2026-02-10
tags: ["linux", "cheatsheet", "sysadmin", "permissions", "devops"]
keywords: ["chmod कैलकुलेटर", "chown उदाहरण", "linux प्रक्रिया समाप्त करें", "linux उपयोगकर्ता प्रबंधन", "systemd कमांड", "linux फ़ाइल अनुमतियाँ", "linux sysadmin चीट शीट", "chmod 755 समझाया", "linux उपयोगकर्ता समूह", "systemctl restart सेवा"]
draft: false
schema_json: >
  {
    "@context": "https://schema.org",
    "@type": "TechArticle",
    "name": "Linux SysAdmin: फ़ाइल अनुमतियाँ, उपयोगकर्ता और प्रक्रिया प्रबंधन",
    "description": "फ़ाइल अनुमतियाँ, उपयोगकर्ता प्रबंधन, systemd सेवाओं और प्रक्रिया नियंत्रण को कवर करने वाले आवश्यक Linux सिस्टम प्रशासन कमांड।",
    "proficiencyLevel": "Intermediate",
    "inLanguage": "hi"
  }
---

## सिस्टम आरंभीकरण

Linux फ़ाइल अनुमतियाँ किसी भी सिस्टम में रक्षा की पहली पंक्ति हैं। गलत तरीके से कॉन्फ़िगर की गई अनुमति संवेदनशील डेटा को अनधिकृत उपयोगकर्ताओं के सामने उजागर कर सकती है, या वैध सेवाओं को उनकी आवश्यक फ़ाइलों तक पहुँचने से रोक सकती है। अनुमतियों के अलावा, उपयोगकर्ताओं, समूहों, सेवाओं और प्रक्रियाओं का प्रबंधन किसी भी सिस्टम प्रशासक का दैनिक कार्य है। यह फ़ील्ड मैनुअल उन कमांड को कवर करता है जिनका आप हर दिन उपयोग करेंगे — वेब सर्वर के डॉक्यूमेंट रूट पर सही अनुमतियाँ सेट करने से लेकर उस बेकाबू प्रक्रिया को समाप्त करने तक जो सारी उपलब्ध मेमोरी खा रही है। प्रत्येक कमांड को वास्तविक परिदृश्यों के लिए व्यावहारिक उदाहरणों के साथ समझाया गया है।

इन कमांड के लिए अधिकांश संचालन में root या sudo एक्सेस आवश्यक है। सावधानी से निष्पादित करें।

---

## फ़ाइल अनुमतियाँ

Linux तीन-स्तरीय अनुमति मॉडल का उपयोग करता है: **स्वामी**, **समूह**, और **अन्य**। प्रत्येक स्तर में **पढ़ने (r=4)**, **लिखने (w=2)**, और **निष्पादन (x=1)** की अनुमतियाँ हो सकती हैं। इस मॉडल को समझना — और इसे दर्शाने वाली संख्यात्मक (ऑक्टल) अंकन प्रणाली — फ़ाइलों, निर्देशिकाओं, स्क्रिप्ट और एप्लिकेशन डेटा को सुरक्षित करने के लिए आवश्यक है। गलत तरीके से कॉन्फ़िगर की गई अनुमतियाँ उत्पादन सर्वरों पर सबसे आम सुरक्षा कमजोरियों में से एक हैं।

### अनुमति अंकन को समझना

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

### chmod — फ़ाइल अनुमतियाँ बदलें

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

### chown — फ़ाइल स्वामित्व बदलें

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

### विशेष अनुमतियाँ संदर्भ

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

## उपयोगकर्ता प्रबंधन

उपयोगकर्ता और समूह प्रबंधन नियंत्रित करता है कि सिस्टम तक कौन पहुँच सकता है और क्या कर सकता है। प्रत्येक प्रक्रिया एक उपयोगकर्ता के रूप में चलती है, प्रत्येक फ़ाइल एक उपयोगकर्ता की होती है, और एक्सेस नियंत्रण उपयोगकर्ता पहचान के आधार पर लागू होता है। उपयोगकर्ताओं का सही प्रबंधन — न्यूनतम विशेषाधिकारों के साथ बनाना, उपयुक्त समूहों में नियुक्त करना, और जब आवश्यकता न हो तो अक्षम करना — सिस्टम सुरक्षा के लिए मूलभूत है।

### उपयोगकर्ता बनाएँ और प्रबंधित करें

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

### समूह प्रबंधित करें

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

### sudo कॉन्फ़िगरेशन

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

## Systemd सेवाएँ

Systemd अधिकांश आधुनिक Linux वितरणों का init सिस्टम और सेवा प्रबंधक है। यह नियंत्रित करता है कि बूट पर कौन सी सेवाएँ शुरू होती हैं, उनके जीवनचक्र का प्रबंधन करता है, सेवाओं के बीच निर्भरताओं को संभालता है, और journald के माध्यम से लॉगिंग प्रदान करता है। चाहे आप वेब सर्वर, डेटाबेस, या कस्टम एप्लिकेशन डेमन चला रहे हों, systemd वह तरीका है जिससे आप उत्पादन में इसे प्रबंधित करते हैं।

### सेवा प्रबंधन

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

### जर्नल लॉग

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

### कस्टम सेवा बनाएँ

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

## प्रक्रिया नियंत्रण

प्रक्रियाएँ आपके सिस्टम पर चल रहे प्रोग्रामों के उदाहरण हैं। उनकी निगरानी और नियंत्रण सिस्टम स्थिरता के लिए आवश्यक है — एक बेकाबू प्रक्रिया सारी CPU या मेमोरी खा सकती है, एक ज़ोंबी प्रक्रिया प्रक्रिया तालिका भर सकती है, और एक अनुत्तरदायी सेवा को पहचानकर पुनः आरंभ करने की आवश्यकता है। ये कमांड आपको प्रक्रियाओं को प्रभावी ढंग से प्रबंधित करने के लिए दृश्यता और नियंत्रण प्रदान करते हैं।

### प्रक्रियाओं की निगरानी

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

### प्रक्रियाएँ समाप्त करें

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

### संसाधन निगरानी

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
