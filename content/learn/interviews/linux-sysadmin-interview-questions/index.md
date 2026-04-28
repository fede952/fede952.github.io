---
title: "Linux SysAdmin Interview: Process, Permissions & Networking"
description: "20 essential Linux system administration interview questions for Senior SysAdmin and DevOps roles. Covers file permissions, process management, systemd, networking, and troubleshooting."
date: 2026-02-11
tags: ["linux", "interview", "sysadmin", "devops"]
keywords: ["linux interview questions", "red hat interview", "bash scripting questions", "linux permissions interview", "sysadmin interview questions", "linux process management", "systemd interview", "linux networking questions", "senior linux engineer", "rhcsa exam prep"]
draft: false
schema_json: >
  {
    "@context": "https://schema.org",
    "@type": "TechArticle",
    "name": "Linux SysAdmin Interview: Process, Permissions & Networking",
    "description": "20 essential Linux system administration interview questions covering permissions, processes, systemd, and networking.",
    "proficiencyLevel": "Advanced",
    "inLanguage": "en"
  }
---

## System Init

Linux system administration is the bedrock of modern infrastructure. Whether you are interviewing for a SysAdmin, DevOps, SRE, or Cloud Engineer role, you will be tested on your ability to manage users, troubleshoot processes, configure networking, and secure servers — all from the command line. This guide covers 20 questions that separate senior candidates from junior ones, with answers that demonstrate real operational experience.

**Need a quick command reference?** Keep our [Linux SysAdmin Cheatsheet](/cheatsheets/linux-sysadmin-permissions/) open during your prep.

---

## File Permissions & Ownership

<details>
<summary><strong>1. Explain the Linux permission model (rwx, octal notation, special bits).</strong></summary>
<br>

Every file has three permission tiers: **Owner**, **Group**, **Others**. Each tier can have **Read (r=4)**, **Write (w=2)**, **Execute (x=1)**.

Octal notation combines these: `chmod 755` = rwxr-xr-x (owner: full, group/others: read+execute).

**Special bits**:
- **SUID (4000)**: File executes as the file owner, not the user running it. Example: `/usr/bin/passwd` runs as root so users can change their own password.
- **SGID (2000)**: On files, executes as the group owner. On directories, new files inherit the directory's group.
- **Sticky bit (1000)**: On directories, only the file owner can delete their files. Classic example: `/tmp`.
</details>

<details>
<summary><strong>2. What is the difference between hard links and soft links?</strong></summary>
<br>

- **Hard link**: A direct reference to the inode (the actual data on disk). Multiple hard links to the same file share the same inode number. Deleting one hard link does not affect others — the data persists until all hard links are removed. Cannot cross filesystem boundaries. Cannot link to directories.
- **Soft link (symlink)**: A pointer to a file path (like a shortcut). Has its own inode. If the target file is deleted, the symlink becomes a dangling link. Can cross filesystems. Can link to directories.

Use `ls -li` to see inode numbers and confirm hard link relationships.
</details>

<details>
<summary><strong>3. A developer cannot write to a shared directory. How do you diagnose and fix it?</strong></summary>
<br>

Diagnostic steps:
1. `ls -la /shared/` — check ownership and permissions.
2. `id developer` — check which groups the user belongs to.
3. `getfacl /shared/` — check for ACLs that might override standard permissions.

Common fixes:
- Add the user to the directory's group: `sudo usermod -aG devteam developer`.
- Set SGID on the directory so new files inherit the group: `chmod g+s /shared/`.
- If ACLs are needed: `setfacl -m u:developer:rwx /shared/`.
- Ensure the umask is not blocking group write (check with `umask` command).
</details>

<details>
<summary><strong>4. What is umask and how does it affect file creation?</strong></summary>
<br>

`umask` defines the default permissions **removed** from new files and directories. It is a bitmask subtracted from the maximum permissions.

- Default max for files: 666 (no execute by default).
- Default max for directories: 777.
- With `umask 022`: files get 644 (rw-r--r--), directories get 755 (rwxr-xr-x).
- With `umask 077`: files get 600 (rw-------), directories get 700 (rwx------).

Set system-wide in `/etc/profile` or per-user in `~/.bashrc`. Critical for security — a permissive umask can expose sensitive files to unauthorized users.
</details>

## Process Management

<details>
<summary><strong>5. Explain the difference between a process, a thread, and a daemon.</strong></summary>
<br>

- **Process**: An instance of a running program with its own memory space, PID, file descriptors, and environment. Created by `fork()` or `exec()`.
- **Thread**: A lightweight execution unit within a process. Threads share the same memory space and file descriptors but have their own stack and registers. Faster to create than processes.
- **Daemon**: A background process that runs without a controlling terminal. Typically started at boot, runs continuously, and provides a service (sshd, nginx, cron). Conventionally named with a `d` suffix.
</details>

<details>
<summary><strong>6. What are zombie processes and how do you handle them?</strong></summary>
<br>

A **zombie** is a process that has finished executing but still has an entry in the process table because its parent hasn't called `wait()` to read its exit status. It consumes no resources except a PID slot.

Identify zombies: `ps aux | grep Z` — they show status `Z` (defunct).

You **cannot** kill a zombie — it's already dead. To remove it:
1. Send `SIGCHLD` to the parent process: `kill -s SIGCHLD <parent_pid>`.
2. If the parent ignores it, killing the parent process will orphan the zombie, which gets adopted by `init` (PID 1). Init automatically calls `wait()` and cleans it up.

A large number of zombies usually indicates a buggy parent process that is not reaping its children.
</details>

<details>
<summary><strong>7. Explain Linux signals. What are SIGTERM, SIGKILL, and SIGHUP?</strong></summary>
<br>

Signals are software interrupts sent to processes:

- **SIGTERM (15)**: Polite termination request. The process can catch it, clean up resources, and exit gracefully. This is what `kill <pid>` sends by default.
- **SIGKILL (9)**: Force kill. Cannot be caught, blocked, or ignored. The kernel terminates the process immediately. Use only as a last resort — no cleanup possible.
- **SIGHUP (1)**: Historically "hangup". Many daemons (nginx, Apache) reload their configuration when they receive SIGHUP, instead of restarting.
- **SIGINT (2)**: Interrupt, sent by Ctrl+C.
- **SIGSTOP/SIGCONT (19/18)**: Pause and resume a process.
</details>

<details>
<summary><strong>8. How do you find and kill a process consuming too much CPU?</strong></summary>
<br>

1. Identify the process: `top -o %CPU` or `ps aux --sort=-%cpu | head -10`.
2. Get details: `ls -l /proc/<pid>/exe` to see the actual binary.
3. Check what it's doing: `strace -p <pid>` for system calls, `lsof -p <pid>` for open files.
4. Graceful stop: `kill <pid>` (SIGTERM) — allow cleanup.
5. Force stop: `kill -9 <pid>` (SIGKILL) — only if SIGTERM fails.
6. Prevent recurrence: If managed by systemd, set `CPUQuota=50%` in the service unit file.
</details>

## Systemd & Services

<details>
<summary><strong>9. What is systemd and how does it differ from SysVinit?</strong></summary>
<br>

**SysVinit**: Sequential boot process using shell scripts in `/etc/init.d/`. Services start one after another in a defined run level. Slow boot times. Simple but limited dependency handling.

**systemd**: Parallel boot process using unit files. Supports dependencies, socket activation, on-demand service starting, cgroups for resource control, and journald for logging. Much faster boot. Manages services, timers, mounts, sockets, and targets.

systemd is the default init system on RHEL, Ubuntu, Debian, Fedora, SUSE, and Arch.
</details>

<details>
<summary><strong>10. How do you create a custom systemd service?</strong></summary>
<br>

Create a unit file in `/etc/systemd/system/myapp.service`:

```ini
[Unit]
Description=My Application
After=network.target

[Service]
Type=simple
User=deploy
WorkingDirectory=/opt/myapp
ExecStart=/opt/myapp/bin/server
Restart=on-failure
RestartSec=5

[Install]
WantedBy=multi-user.target
```

Then: `sudo systemctl daemon-reload && sudo systemctl enable --now myapp`.

Key `Type` values: `simple` (default, main process runs in foreground), `forking` (process forks to background, needs `PIDFile`), `oneshot` (runs once and exits), `notify` (process signals readiness via sd_notify).
</details>

<details>
<summary><strong>11. How do you analyze boot performance with systemd?</strong></summary>
<br>

- `systemd-analyze` — total boot time.
- `systemd-analyze blame` — list of services sorted by start time.
- `systemd-analyze critical-chain` — tree of the critical boot path.
- `systemd-analyze plot > boot.svg` — generate a visual timeline of the boot sequence.
- `journalctl -b -p err` — errors from the current boot.

To speed up boot: disable unnecessary services (`systemctl disable`), switch services to socket activation (start on demand), and identify slow services from the blame output.
</details>

## Networking

<details>
<summary><strong>12. Explain the TCP three-way handshake.</strong></summary>
<br>

1. **SYN**: Client sends a SYN packet to the server with an initial sequence number.
2. **SYN-ACK**: Server responds with SYN-ACK, acknowledging the client's SYN and sending its own sequence number.
3. **ACK**: Client sends an ACK confirming the server's sequence number. Connection is established.

Teardown uses a four-way handshake: FIN → ACK → FIN → ACK (each side independently closes its half of the connection).

Debug with: `ss -tuln` (listening ports), `ss -tulnp` (with process names), `tcpdump -i eth0 port 80` (packet capture).
</details>

<details>
<summary><strong>13. What is the difference between TCP and UDP?</strong></summary>
<br>

- **TCP** (Transmission Control Protocol): Connection-oriented, reliable, ordered delivery. Uses handshake, acknowledgments, retransmissions. Higher overhead. Used for HTTP, SSH, FTP, databases.
- **UDP** (User Datagram Protocol): Connectionless, unreliable, no guaranteed order. No handshake, no acknowledgments. Lower overhead, lower latency. Used for DNS, DHCP, VoIP, streaming, gaming.

Key insight: "Unreliable" doesn't mean bad — it means the application handles reliability if needed. DNS uses UDP because queries are small and fast; if a response is lost, the client simply re-sends.
</details>

<details>
<summary><strong>14. A server cannot reach an external IP. How do you troubleshoot?</strong></summary>
<br>

Layer-by-layer approach:
1. **L1 - Physical**: `ip link show` — is the interface up?
2. **L2 - Data Link**: `ip neighbor show` — ARP table populated?
3. **L3 - Network**: `ip route show` — is there a default gateway? `ping <gateway>` — can you reach it?
4. **L3 - External**: `ping 8.8.8.8` — can you reach the internet by IP?
5. **L7 - DNS**: `nslookup google.com` — is DNS resolution working? Check `/etc/resolv.conf`.
6. **Firewall**: `iptables -L -n` or `nft list ruleset` — are outbound connections blocked?
7. **Route trace**: `traceroute 8.8.8.8` — where does the path break?
</details>

## Storage & Filesystems

<details>
<summary><strong>15. What is an inode?</strong></summary>
<br>

An inode is a data structure that stores metadata about a file: permissions, ownership, size, timestamps, and pointers to the data blocks on disk. Every file and directory has an inode.

Crucially, the **filename is NOT stored in the inode** — it is stored in the directory entry, which maps a name to an inode number. This is why hard links work: multiple directory entries can point to the same inode.

Running out of inodes (even with free disk space) prevents creating new files. Check with `df -i`. Common cause: millions of tiny files (mail queues, cache directories).
</details>

<details>
<summary><strong>16. How do you extend an LVM logical volume without downtime?</strong></summary>
<br>

1. Check available space: `vgdisplay` — look at Free PE (physical extents).
2. If no free space, add a new physical disk: `pvcreate /dev/sdb && vgextend myvg /dev/sdb`.
3. Extend the logical volume: `lvextend -L +10G /dev/myvg/mylv`.
4. Resize the filesystem (online for ext4/XFS):
   - ext4: `resize2fs /dev/myvg/mylv`
   - XFS: `xfs_growfs /mountpoint`

No unmount needed. No downtime. This is one of the primary advantages of LVM over raw partitions.
</details>

## Security & Hardening

<details>
<summary><strong>17. What is the difference between su, sudo, and sudoers?</strong></summary>
<br>

- **su** (switch user): Changes to another user entirely. `su -` loads the target user's environment. Requires the target user's password.
- **sudo** (superuser do): Runs a single command as another user (usually root). Requires the **caller's** password. Provides audit logging of who ran what.
- **sudoers** (`/etc/sudoers`): Configuration file that defines who can use sudo and what commands they can run. Edited safely with `visudo` (syntax validation).

Best practice: Disable direct root login (`PermitRootLogin no` in sshd_config). Give admins sudo access instead — it provides accountability (logs who did what) and granular control.
</details>

<details>
<summary><strong>18. How do you harden an SSH server?</strong></summary>
<br>

Essential `/etc/ssh/sshd_config` changes:
- `PermitRootLogin no` — prevent direct root login.
- `PasswordAuthentication no` — force key-based authentication.
- `PubkeyAuthentication yes` — enable SSH keys.
- `Port 2222` — move off default port (reduces automated scans).
- `MaxAuthTries 3` — limit authentication attempts.
- `AllowUsers deploy admin` — whitelist specific users.
- `ClientAliveInterval 300` — disconnect idle sessions.
- Install `fail2ban` — automatically ban IPs after failed login attempts.
</details>

## Scripting & Automation

<details>
<summary><strong>19. What is the difference between $?, $$, $!, and $@ in Bash?</strong></summary>
<br>

- **$?** — Exit status of the last command (0 = success, non-zero = failure).
- **$$** — PID of the current shell.
- **$!** — PID of the last background process.
- **$@** — All arguments passed to the script (each as a separate word).
- **$#** — Number of arguments.
- **$0** — Name of the script itself.
- **$1, $2, ...** — Individual positional arguments.

Common pattern: `command && echo "success" || echo "fail"` uses `$?` implicitly.
</details>

<details>
<summary><strong>20. Write a one-liner to find all files larger than 100MB modified in the last 7 days.</strong></summary>
<br>

```bash
find / -type f -size +100M -mtime -7 -exec ls -lh {} \; 2>/dev/null
```

Breakdown:
- `find /` — search from root.
- `-type f` — files only (not directories).
- `-size +100M` — larger than 100 megabytes.
- `-mtime -7` — modified within the last 7 days.
- `-exec ls -lh {} \;` — show human-readable size for each result.
- `2>/dev/null` — suppress permission denied errors.

Alternative with sort: `find / -type f -size +100M -mtime -7 -printf '%s %p\n' 2>/dev/null | sort -rn | head -20`.
</details>
