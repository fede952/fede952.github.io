---
title: "Chmod Calculator: Linux File Permissions"
description: "Toggle read, write and execute for owner, group and others to get the chmod octal number (755, 644…), the rwx string and a ready-to-copy chmod command."
intro: "Click the permission switches and get the **chmod** number, the `rwxr-xr-x` string you see in `ls -l` and a ready-to-run command. Presets cover the common cases: 755, 644, 600, 444 and the one to avoid, 777."
date: 2026-02-14
lastmod: 2026-10-24
reviewed: false
keywords: ["chmod calculator", "chmod 755", "linux file permissions", "chmod 644", "octal permissions calculator", "rwx permissions", "unix permissions calculator", "chmod command generator"]
tags: ["linux", "sysadmin", "permissions", "tool"]
app_category: "DeveloperApplication"
tool_partial: "chmod-calculator"
howto:
  - "For each class (**Owner**, **Group**, **Others**) switch **Read**, **Write** and **Execute** on or off. The default is 755."
  - "Read the octal number after `chmod` and the symbolic string below it, the same notation `ls -l` prints."
  - "Type the target in the file name field; names with spaces or shell characters are quoted automatically in the copied command."
  - "Or start from a **preset**: 755 for scripts and directories, 644 for regular files, 600 for private keys, 444 for read-only files."
  - "Press **Copy command** and paste it into your terminal."
faq:
  - q: "What does chmod 755 mean?"
    a: "7 for the owner (read 4 + write 2 + execute 1), 5 for the group (read 4 + execute 1) and 5 for others. The owner can do everything; everyone else can read and execute but not modify. It is the standard for scripts, binaries and directories."
  - q: "What is the difference between 644 and 755?"
    a: "644 (`rw-r--r--`) has no execute bit: right for documents, configs and web files. 755 (`rwxr-xr-x`) adds execute for everyone: needed for scripts and programs, and for directories, where \"execute\" means permission to enter them."
  - q: "Why is chmod 777 dangerous?"
    a: "It lets every user on the system modify the file or directory. On a shared server or a web root, any compromised process can then replace your code or plant files. If something only works with 777, the real fix is usually the file's owner or group (`chown`), not wider permissions."
  - q: "What permissions should an SSH private key have?"
    a: "600 (`rw-------`): readable and writable by you only. OpenSSH refuses to use a private key that others can read and prints \"UNPROTECTED PRIVATE KEY FILE\". The `~/.ssh` directory itself should be 700."
  - q: "What does execute mean on a directory?"
    a: "It is the permission to traverse the directory: `cd` into it and access files inside by name. Read on a directory lets you list its names; without execute you can see the names but not open the files. That is why directories are usually 755 or 700."
  - q: "Does it support setuid, setgid or the sticky bit?"
    a: "No. The calculator covers the nine basic permission bits, the three-digit mode used in almost every `chmod` command. The special bits are a fourth, leading digit (4 setuid, 2 setgid, 1 sticky, as in `chmod 1777 /tmp`); add it by hand if you need it."
---

## How it works

Unix permissions are nine bits in three groups of three. Each group answers the same three questions, read, write, execute, for one class of users: the file's **owner** (`u`), its **group** (`g`) and everyone else, **others** (`o`).

Each permission has a fixed value, and a digit is simply their sum:

| Permission | Value | Symbol |
|---|---|---|
| Read | 4 | `r` |
| Write | 2 | `w` |
| Execute | 1 | `x` |

So 7 = 4 + 2 + 1 = `rwx`, 6 = 4 + 2 = `rw-`, 5 = 4 + 1 = `r-x` and 4 = `r--`. The calculator adds up the active switches per class, writes the three digits side by side and converts each digit back to `r`, `w`, `x` or `-` with a bitwise test (`digit & 4`, `& 2`, `& 1`). The leading `-` in the symbolic string is the file-type character `ls -l` shows for a regular file (`d` for a directory).

Presets do the reverse: each digit of `644` is split back into its bits to set the nine switches.

The copied command is `chmod <octal> <file>`. If the name contains anything other than letters, digits and `._/@%+=:,-`, it is wrapped in single quotes (`'my file.sh'`), with embedded quotes escaped the POSIX way, so the command can be pasted safely into bash or zsh.

### Common modes

| Mode | Symbolic | Typical use |
|---|---|---|
| 755 | `rwxr-xr-x` | Scripts, binaries, directories |
| 644 | `rw-r--r--` | Regular files, configs, web assets |
| 700 | `rwx------` | Private directories such as `~/.ssh` |
| 600 | `rw-------` | Private keys, `.env` files, credentials |
| 444 | `r--r--r--` | Files nobody should modify |
| 777 | `rwxrwxrwx` | Almost never: anyone can change it |

## Use cases

- **"Permission denied" when running a script.** Add the execute bit: `chmod 755 deploy.sh`, or `chmod u+x` if only you run it.
- **Hardening secrets.** Set `.env` files, API key files and SSH keys to 600 so other users on the machine cannot read them.
- **Web servers.** Typical setups use 644 for files and 755 for directories, owned by the deploy user and readable by the web server.
- **Docker and CI.** Files copied into images or checked out by CI sometimes lose their execute bit; the calculator gives you the exact `RUN chmod` line.
- **Learning the notation.** Translate between `ls -l` output and octal numbers until reading `drwxr-x---` becomes automatic.
