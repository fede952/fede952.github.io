---
title: "Nmap Feldhandbuch: Netzwerk-Aufklärungsbefehle"
description: "Wesentliche Nmap-Befehle für Netzwerkscans, Host-Erkennung, Port-Enumeration, Service-Erkennung und Schwachstellenbewertung. Eine taktische Schnellreferenz für Penetrationstester."
date: 2026-02-10
tags: ["nmap", "cheatsheet", "penetration-testing", "network-security", "reconnaissance"]
keywords: ["nmap cheatsheet", "nmap befehle", "netzwerk-scan anleitung", "nmap port-scan", "nmap service-erkennung", "nmap scripts NSE", "nmap schwachstellen-scan", "penetration testing befehle"]
draft: false
schema_json: >
  {
    "@context": "https://schema.org",
    "@type": "TechArticle",
    "name": "Nmap Feldhandbuch: Netzwerk-Aufklärungsbefehle",
    "description": "Wesentliche Nmap-Befehle für Netzwerkscans, Host-Erkennung, Port-Enumeration und Schwachstellenbewertung.",
    "proficiencyLevel": "Intermediate",
    "inLanguage": "de"
  }
---

## $ System_Init

Nmap ist das erste geladene Tool bei jeder Aufklärungsaktivität. Es kartiert die Angriffsfläche, identifiziert aktive Hosts, enumeriert offene Ports, identifiziert Dienste und erkennt Schwachstellen — alles aus einer einzigen Binärdatei. Dieses Feldhandbuch liefert die exakten Befehle für jede Phase der Netzwerkaufklärung.

Alle Befehle setzen autorisierte Tests voraus. Verantwortungsvoll einsetzen.

---

## $ Host_Discovery

Identifizieren Sie aktive Ziele im Netzwerk vor dem Port-Scan.

### Ping-Sweep (ICMP echo)

```bash
# Aktive Hosts in einem Subnetz mittels ICMP-Ping ermitteln
nmap -sn 192.168.1.0/24
```

### ARP-Erkennung (nur lokales Netzwerk)

```bash
# ARP-Anfragen zur Host-Erkennung im lokalen LAN verwenden (schnellste Methode)
nmap -sn -PR 192.168.1.0/24
```

### TCP SYN-Erkennung auf spezifischen Ports

```bash
# Hosts durch Senden von SYN-Paketen an gängige Ports ermitteln
nmap -sn -PS22,80,443 10.0.0.0/24
```

### DNS-Auflösung deaktivieren (Scans beschleunigen)

```bash
# Reverse-DNS-Lookups überspringen für schnellere Ergebnisse
nmap -sn -n 192.168.1.0/24
```

### Listen-Scan (keine Pakete gesendet)

```bash
# Ziele auflisten, die gescannt würden, ohne Pakete zu senden
nmap -sL 192.168.1.0/24
```

---

## $ Port_Scanning

Offene Ports enumerieren, um die Angriffsfläche des Ziels zu kartieren.

### SYN-Scan (Stealth-Scan — Standard)

```bash
# Half-Open-Scan: sendet SYN, empfängt SYN/ACK, sendet RST (schließt Handshake nie ab)
sudo nmap -sS 192.168.1.100
```

### TCP-Connect-Scan (erfordert kein Root)

```bash
# Vollständiger TCP-Handshake-Scan (langsamer, funktioniert aber ohne erhöhte Rechte)
nmap -sT 192.168.1.100
```

### UDP-Scan

```bash
# Offene UDP-Ports scannen (langsamer aufgrund des Protokollverhaltens)
sudo nmap -sU 192.168.1.100
```

### Spezifische Ports scannen

```bash
# Nur spezifische Ports scannen
nmap -p 22,80,443,8080 192.168.1.100

# Einen Port-Bereich scannen
nmap -p 1-1024 192.168.1.100

# Alle 65535 Ports scannen
nmap -p- 192.168.1.100
```

### Top-Ports-Scan

```bash
# Die 100 am häufigsten offenen Ports scannen
nmap --top-ports 100 192.168.1.100
```

### Schneller Scan (Top 100 Ports)

```bash
# Schneller Scan mit reduzierter Port-Anzahl für schnelle Bewertung
nmap -F 192.168.1.100
```

---

## $ Service_Detection

Identifizieren Sie, welche Software auf jedem offenen Port läuft.

### Versionserkennung

```bash
# Offene Ports untersuchen, um Service-Name und Version zu bestimmen
nmap -sV 192.168.1.100
```

### Aggressive Versionserkennung

```bash
# Erkennungsintensität erhöhen (1-9, Standard 7)
nmap -sV --version-intensity 9 192.168.1.100
```

### OS-Fingerprinting

```bash
# Das Betriebssystem des Ziels mittels TCP/IP-Stack-Analyse erkennen
sudo nmap -O 192.168.1.100
```

### Kombinierte Service- + OS-Erkennung

```bash
# Vollständige Service-Enumeration mit OS-Fingerprinting
sudo nmap -sV -O 192.168.1.100
```

### Aggressiver Scan (OS + Version + Scripts + Traceroute)

```bash
# Alle Erkennungsfunktionen in einem Flag aktivieren
sudo nmap -A 192.168.1.100
```

---

## $ NSE_Scripts

Nmap Scripting Engine — automatisierte Schwachstellenerkennung und Enumeration.

### Standard-Scripts ausführen

```bash
# Den Standard-Satz sicherer, informativer Scripts ausführen
nmap -sC 192.168.1.100
```

### Ein spezifisches Script ausführen

```bash
# Ein einzelnes NSE-Script nach Name ausführen
nmap --script=http-title 192.168.1.100
```

### Script-Kategorien ausführen

```bash
# Alle Schwachstellenerkennungs-Scripts ausführen
nmap --script=vuln 192.168.1.100

# Alle Discovery-Scripts ausführen
nmap --script=discovery 192.168.1.100

# Brute-Force-Scripts gegen Authentifizierungsdienste ausführen
nmap --script=brute 192.168.1.100
```

### HTTP-Enumeration

```bash
# Webserver-Verzeichnisse und -Dateien enumerieren
nmap --script=http-enum 192.168.1.100

# Web Application Firewalls erkennen
nmap --script=http-waf-detect 192.168.1.100
```

### SMB-Enumeration

```bash
# SMB-Freigaben und Benutzer enumerieren (Windows-Netzwerke)
nmap --script=smb-enum-shares,smb-enum-users 192.168.1.100
```

### SSL/TLS-Analyse

```bash
# SSL-Zertifikatsdetails und Cipher-Suites prüfen
nmap --script=ssl-cert,ssl-enum-ciphers -p 443 192.168.1.100
```

---

## $ Evasion_Techniques

Firewalls und IDS bei autorisierten Penetrationstests umgehen.

### Pakete fragmentieren

```bash
# Sonde-Pakete in kleinere Fragmente aufteilen, um einfache Paketfilter zu umgehen
sudo nmap -f 192.168.1.100
```

### Decoy-Scan

```bash
# Gefälschte Quell-IPs generieren, um den echten Scanner zu maskieren
sudo nmap -D RND:10 192.168.1.100
```

### Quell-Port fälschen

```bash
# Einen vertrauenswürdigen Quell-Port verwenden, um portbasierte Firewall-Regeln zu umgehen
sudo nmap --source-port 53 192.168.1.100
```

### Timing-Steuerung

```bash
# T0=Paranoid, T1=Sneaky, T2=Polite, T3=Normal, T4=Aggressive, T5=Insane
nmap -T2 192.168.1.100
```

### Idle-Scan (Zombie-Scan)

```bash
# Einen Dritt-"Zombie"-Host verwenden, um zu scannen, ohne Ihre IP preiszugeben
sudo nmap -sI zombie-host.com 192.168.1.100
```

---

## $ Output_Formats

Scan-Ergebnisse für Dokumentation und Nachbearbeitung speichern.

### Normale Ausgabe

```bash
# Ergebnisse in menschenlesbarem Format speichern
nmap -oN scan_results.txt 192.168.1.100
```

### XML-Ausgabe (für Tools)

```bash
# Ergebnisse im XML-Format speichern (von Metasploit usw. analysierbar)
nmap -oX scan_results.xml 192.168.1.100
```

### Grep-bare Ausgabe

```bash
# Ergebnisse in grep-freundlichem Format für Scripting speichern
nmap -oG scan_results.gnmap 192.168.1.100
```

### Alle Formate gleichzeitig

```bash
# In normalen, XML- und grep-baren Formaten gleichzeitig speichern
nmap -oA full_scan 192.168.1.100
```

---

## $ Mission_Templates

Kopier-Einfüg-Befehlsketten für gängige Engagement-Szenarien.

### Schnelle Aufklärung

```bash
# Schnelle Erstbewertung eines Ziels
nmap -sS -sV -F -T4 --open 192.168.1.100
```

### Vollständiger Port-Scan mit Service-Erkennung

```bash
# Umfassender Scan aller Ports mit Versionserkennung
sudo nmap -sS -sV -p- -T4 -oA full_scan 192.168.1.100
```

### Schwachstellenbewertung

```bash
# Service-Erkennung plus Schwachstellen-Scripts
sudo nmap -sV --script=vuln -oA vuln_scan 192.168.1.100
```

### Stealth-Aufklärung (minimaler Fußabdruck)

```bash
# Low-Profile-Scan für Umgebungen mit aktiver Überwachung
sudo nmap -sS -T2 -f --data-length 24 -D RND:5 -oA stealth_scan 192.168.1.100
```
