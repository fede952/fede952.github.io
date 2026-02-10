---
title: "Nmap Field Manual: Network Reconnaissance Commands"
description: "Essential Nmap commands for network scanning, host discovery, port enumeration, service detection, and vulnerability assessment. A tactical quick-reference for penetration testers."
date: 2026-02-10
tags: ["nmap", "cheatsheet", "penetration-testing", "network-security", "reconnaissance"]
keywords: ["nmap cheatsheet", "nmap commands", "network scanning guide", "nmap port scan", "nmap service detection", "nmap scripts NSE", "nmap vulnerability scan", "penetration testing commands"]
draft: false
schema_json: >
  {
    "@context": "https://schema.org",
    "@type": "TechArticle",
    "name": "Nmap Field Manual: Network Reconnaissance Commands",
    "description": "Essential Nmap commands for network scanning, host discovery, port enumeration, and vulnerability assessment.",
    "proficiencyLevel": "Intermediate",
    "inLanguage": "en"
  }
---

## System Init

Nmap is the first tool loaded in any reconnaissance engagement. It maps the attack surface, identifies live hosts, enumerates open ports, fingerprints services, and detects vulnerabilities — all from a single binary. This field manual provides the exact commands for each phase of network reconnaissance.

All commands assume authorized testing. Deploy responsibly.

---

## Host Discovery

Identify live targets on the network before port scanning.

### Ping sweep (ICMP echo)

```bash
# Discover live hosts on a subnet using ICMP ping
nmap -sn 192.168.1.0/24
```

### ARP discovery (local network only)

```bash
# Use ARP requests for host discovery on the local LAN (fastest method)
nmap -sn -PR 192.168.1.0/24
```

### TCP SYN discovery on specific ports

```bash
# Discover hosts by sending SYN packets to common ports
nmap -sn -PS22,80,443 10.0.0.0/24
```

### Disable DNS resolution (speed up scans)

```bash
# Skip reverse DNS lookups for faster results
nmap -sn -n 192.168.1.0/24
```

### List scan (no packets sent)

```bash
# List targets that would be scanned without sending any packets
nmap -sL 192.168.1.0/24
```

---

## Port Scanning

Enumerate open ports to map the target's attack surface.

### SYN scan (stealth scan — default)

```bash
# Half-open scan: sends SYN, receives SYN/ACK, sends RST (never completes handshake)
sudo nmap -sS 192.168.1.100
```

### TCP connect scan (no root required)

```bash
# Full TCP handshake scan (slower but works without elevated privileges)
nmap -sT 192.168.1.100
```

### UDP scan

```bash
# Scan for open UDP ports (slower due to protocol behavior)
sudo nmap -sU 192.168.1.100
```

### Scan specific ports

```bash
# Scan only specific ports
nmap -p 22,80,443,8080 192.168.1.100

# Scan a port range
nmap -p 1-1024 192.168.1.100

# Scan all 65535 ports
nmap -p- 192.168.1.100
```

### Top ports scan

```bash
# Scan the 100 most commonly open ports
nmap --top-ports 100 192.168.1.100
```

### Fast scan (top 100 ports)

```bash
# Quick scan with reduced port count for rapid assessment
nmap -F 192.168.1.100
```

---

## Service Detection

Identify what software is running on each open port.

### Version detection

```bash
# Probe open ports to determine service name and version
nmap -sV 192.168.1.100
```

### Aggressive version detection

```bash
# Increase detection intensity (1-9, default 7)
nmap -sV --version-intensity 9 192.168.1.100
```

### OS fingerprinting

```bash
# Detect the target's operating system using TCP/IP stack analysis
sudo nmap -O 192.168.1.100
```

### Combined service + OS detection

```bash
# Full service enumeration with OS fingerprinting
sudo nmap -sV -O 192.168.1.100
```

### Aggressive scan (OS + version + scripts + traceroute)

```bash
# Enable all detection features in one flag
sudo nmap -A 192.168.1.100
```

---

## NSE Scripts

Nmap Scripting Engine — automated vulnerability detection and enumeration.

### Run default scripts

```bash
# Execute the default set of safe, informational scripts
nmap -sC 192.168.1.100
```

### Run a specific script

```bash
# Execute a single NSE script by name
nmap --script=http-title 192.168.1.100
```

### Run script categories

```bash
# Run all vulnerability detection scripts
nmap --script=vuln 192.168.1.100

# Run all discovery scripts
nmap --script=discovery 192.168.1.100

# Run brute-force scripts against authentication services
nmap --script=brute 192.168.1.100
```

### HTTP enumeration

```bash
# Enumerate web server directories and files
nmap --script=http-enum 192.168.1.100

# Detect web application firewalls
nmap --script=http-waf-detect 192.168.1.100
```

### SMB enumeration

```bash
# Enumerate SMB shares and users (Windows networks)
nmap --script=smb-enum-shares,smb-enum-users 192.168.1.100
```

### SSL/TLS analysis

```bash
# Check SSL certificate details and cipher suites
nmap --script=ssl-cert,ssl-enum-ciphers -p 443 192.168.1.100
```

---

## Evasion Techniques

Bypass firewalls and IDS during authorized penetration tests.

### Fragment packets

```bash
# Split probe packets into smaller fragments to bypass simple packet filters
sudo nmap -f 192.168.1.100
```

### Decoy scan

```bash
# Generate spoofed source IPs to mask the real scanner
sudo nmap -D RND:10 192.168.1.100
```

### Spoof source port

```bash
# Use a trusted source port to bypass port-based firewall rules
sudo nmap --source-port 53 192.168.1.100
```

### Timing control

```bash
# T0=Paranoid, T1=Sneaky, T2=Polite, T3=Normal, T4=Aggressive, T5=Insane
nmap -T2 192.168.1.100
```

### Idle scan (zombie scan)

```bash
# Use a third-party "zombie" host to scan without revealing your IP
sudo nmap -sI zombie-host.com 192.168.1.100
```

---

## Output Formats

Save scan results for documentation and post-processing.

### Normal output

```bash
# Save results in human-readable format
nmap -oN scan_results.txt 192.168.1.100
```

### XML output (for tools)

```bash
# Save results in XML format (parseable by Metasploit, etc.)
nmap -oX scan_results.xml 192.168.1.100
```

### Grepable output

```bash
# Save results in grep-friendly format for scripting
nmap -oG scan_results.gnmap 192.168.1.100
```

### All formats at once

```bash
# Save in normal, XML, and grepable formats simultaneously
nmap -oA full_scan 192.168.1.100
```

---

## Mission Templates

Copy-paste command chains for common engagement scenarios.

### Quick reconnaissance

```bash
# Fast initial assessment of a target
nmap -sS -sV -F -T4 --open 192.168.1.100
```

### Full port scan with service detection

```bash
# Comprehensive scan of all ports with version detection
sudo nmap -sS -sV -p- -T4 -oA full_scan 192.168.1.100
```

### Vulnerability assessment

```bash
# Service detection plus vulnerability scripts
sudo nmap -sV --script=vuln -oA vuln_scan 192.168.1.100
```

### Stealth recon (minimal footprint)

```bash
# Low-profile scan for environments with active monitoring
sudo nmap -sS -T2 -f --data-length 24 -D RND:5 -oA stealth_scan 192.168.1.100
```
