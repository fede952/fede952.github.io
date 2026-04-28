---
title: "Linux SysAdmin Interview: Prozesse, Berechtigungen & Netzwerk"
description: "20 wesentliche Interview-Fragen zur Linux-Systemadministration für Senior SysAdmin- und DevOps-Rollen. Behandelt Dateiberechtigungen, Prozessverwaltung, systemd, Netzwerk und Fehlerbehebung."
date: 2026-02-11
tags: ["linux", "interview", "sysadmin", "devops"]
keywords: ["linux interview questions", "red hat interview", "bash scripting questions", "linux permissions interview", "sysadmin interview questions", "linux process management", "systemd interview", "linux networking questions", "senior linux engineer", "rhcsa exam prep"]
draft: false
schema_json: >
  {
    "@context": "https://schema.org",
    "@type": "TechArticle",
    "name": "Linux SysAdmin Interview: Prozesse, Berechtigungen & Netzwerk",
    "description": "20 wesentliche Interview-Fragen zur Linux-Systemadministration über Berechtigungen, Prozesse, systemd und Netzwerk.",
    "proficiencyLevel": "Advanced",
    "inLanguage": "de"
  }
---

## Systeminitialisierung

Linux-Systemadministration ist das Fundament moderner Infrastruktur. Ob Sie sich für eine SysAdmin-, DevOps-, SRE- oder Cloud-Engineer-Rolle bewerben — Sie werden auf Ihre Fähigkeit geprüft, Benutzer zu verwalten, Prozesse zu debuggen, Netzwerke zu konfigurieren und Server abzusichern — alles von der Kommandozeile aus. Dieser Leitfaden behandelt 20 Fragen, die Senior-Kandidaten von Junior-Kandidaten unterscheiden, mit Antworten, die echte operative Erfahrung demonstrieren.

**Brauchen Sie eine schnelle Befehlsreferenz?** Halten Sie unser [Linux SysAdmin Cheatsheet](/cheatsheets/linux-sysadmin-permissions/) während Ihrer Vorbereitung geöffnet.

---

## Dateiberechtigungen & Eigentümerschaft

<details>
<summary><strong>1. Erklären Sie das Linux-Berechtigungsmodell (rwx, Oktalnotation, Spezialbits).</strong></summary>
<br>

Jede Datei hat drei Berechtigungsebenen: **Eigentümer**, **Gruppe**, **Andere**. Jede Ebene kann **Lesen (r=4)**, **Schreiben (w=2)**, **Ausführen (x=1)** haben.

Die Oktalnotation kombiniert diese: `chmod 755` = rwxr-xr-x (Eigentümer: voll, Gruppe/Andere: Lesen+Ausführen).

**Spezialbits**:
- **SUID (4000)**: Die Datei wird als Dateieigentümer ausgeführt, nicht als der Benutzer, der sie startet. Beispiel: `/usr/bin/passwd` läuft als root, damit Benutzer ihr eigenes Passwort ändern können.
- **SGID (2000)**: Bei Dateien wird als Gruppenbesitzer ausgeführt. Bei Verzeichnissen erben neue Dateien die Gruppe des Verzeichnisses.
- **Sticky Bit (1000)**: Bei Verzeichnissen kann nur der Dateieigentümer seine Dateien löschen. Klassisches Beispiel: `/tmp`.
</details>

<details>
<summary><strong>2. Was ist der Unterschied zwischen Hardlinks und Softlinks?</strong></summary>
<br>

- **Hardlink**: Ein direkter Verweis auf den Inode (die tatsächlichen Daten auf der Festplatte). Mehrere Hardlinks zur selben Datei teilen sich die gleiche Inode-Nummer. Das Löschen eines Hardlinks beeinflusst die anderen nicht — die Daten bestehen fort, bis alle Hardlinks entfernt werden. Kann keine Dateisystemgrenzen überschreiten. Kann nicht auf Verzeichnisse verweisen.
- **Softlink (Symlink)**: Ein Zeiger auf einen Dateipfad (wie eine Verknüpfung). Hat seinen eigenen Inode. Wenn die Zieldatei gelöscht wird, wird der Symlink zu einem hängenden Link. Kann Dateisysteme überschreiten. Kann auf Verzeichnisse verweisen.

Verwenden Sie `ls -li`, um Inode-Nummern zu sehen und Hardlink-Beziehungen zu bestätigen.
</details>

<details>
<summary><strong>3. Ein Entwickler kann nicht in ein gemeinsames Verzeichnis schreiben. Wie diagnostizieren und beheben Sie das Problem?</strong></summary>
<br>

Diagnoseschritte:
1. `ls -la /shared/` — Eigentümerschaft und Berechtigungen prüfen.
2. `id developer` — prüfen, zu welchen Gruppen der Benutzer gehört.
3. `getfacl /shared/` — nach ACLs suchen, die Standardberechtigungen überschreiben könnten.

Gängige Lösungen:
- Den Benutzer zur Gruppe des Verzeichnisses hinzufügen: `sudo usermod -aG devteam developer`.
- SGID auf das Verzeichnis setzen, damit neue Dateien die Gruppe erben: `chmod g+s /shared/`.
- Falls ACLs benötigt werden: `setfacl -m u:developer:rwx /shared/`.
- Sicherstellen, dass die umask das Gruppenschreiben nicht blockiert (mit dem Befehl `umask` prüfen).
</details>

<details>
<summary><strong>4. Was ist umask und wie beeinflusst es die Dateierstellung?</strong></summary>
<br>

`umask` definiert die Standardberechtigungen, die von neuen Dateien und Verzeichnissen **entfernt** werden. Es ist eine Bitmaske, die von den maximalen Berechtigungen abgezogen wird.

- Standardmaximum für Dateien: 666 (standardmäßig keine Ausführung).
- Standardmaximum für Verzeichnisse: 777.
- Mit `umask 022`: Dateien erhalten 644 (rw-r--r--), Verzeichnisse erhalten 755 (rwxr-xr-x).
- Mit `umask 077`: Dateien erhalten 600 (rw-------), Verzeichnisse erhalten 700 (rwx------).

Systemweit in `/etc/profile` oder benutzerspezifisch in `~/.bashrc` gesetzt. Kritisch für die Sicherheit — eine zu permissive umask kann sensible Dateien für unbefugte Benutzer zugänglich machen.
</details>

## Prozessverwaltung

<details>
<summary><strong>5. Erklären Sie den Unterschied zwischen einem Prozess, einem Thread und einem Daemon.</strong></summary>
<br>

- **Prozess**: Eine Instanz eines laufenden Programms mit eigenem Speicherbereich, PID, Dateideskriptoren und Umgebung. Erstellt durch `fork()` oder `exec()`.
- **Thread**: Eine leichtgewichtige Ausführungseinheit innerhalb eines Prozesses. Threads teilen sich den gleichen Speicherbereich und die Dateideskriptoren, haben aber ihren eigenen Stack und eigene Register. Schneller zu erstellen als Prozesse.
- **Daemon**: Ein Hintergrundprozess, der ohne kontrollierendes Terminal läuft. Wird typischerweise beim Booten gestartet, läuft kontinuierlich und stellt einen Dienst bereit (sshd, nginx, cron). Konventionell mit dem Suffix `d` benannt.
</details>

<details>
<summary><strong>6. Was sind Zombie-Prozesse und wie gehen Sie damit um?</strong></summary>
<br>

Ein **Zombie** ist ein Prozess, der seine Ausführung beendet hat, aber noch einen Eintrag in der Prozesstabelle hat, weil sein Elternprozess `wait()` nicht aufgerufen hat, um seinen Exit-Status zu lesen. Er verbraucht keine Ressourcen außer einem PID-Platz.

Zombies identifizieren: `ps aux | grep Z` — sie zeigen den Status `Z` (defunct).

Sie **können** einen Zombie nicht töten — er ist bereits tot. Um ihn zu entfernen:
1. Senden Sie `SIGCHLD` an den Elternprozess: `kill -s SIGCHLD <parent_pid>`.
2. Wenn der Elternprozess es ignoriert, wird das Töten des Elternprozesses den Zombie verwaisen lassen, der dann von `init` (PID 1) adoptiert wird. Init ruft automatisch `wait()` auf und räumt ihn auf.

Eine große Anzahl von Zombies weist normalerweise auf einen fehlerhaften Elternprozess hin, der seine Kindprozesse nicht einsammelt.
</details>

<details>
<summary><strong>7. Erklären Sie Linux-Signale. Was sind SIGTERM, SIGKILL und SIGHUP?</strong></summary>
<br>

Signale sind Software-Interrupts, die an Prozesse gesendet werden:

- **SIGTERM (15)**: Höfliche Beendigungsanfrage. Der Prozess kann es abfangen, Ressourcen aufräumen und sauber beenden. Dies ist, was `kill <pid>` standardmäßig sendet.
- **SIGKILL (9)**: Erzwungenes Beenden. Kann nicht abgefangen, blockiert oder ignoriert werden. Der Kernel beendet den Prozess sofort. Nur als letzten Ausweg verwenden — kein Aufräumen möglich.
- **SIGHUP (1)**: Historisch "Aufhängen". Viele Daemons (nginx, Apache) laden ihre Konfiguration neu, wenn sie SIGHUP erhalten, anstatt neu zu starten.
- **SIGINT (2)**: Unterbrechung, gesendet durch Ctrl+C.
- **SIGSTOP/SIGCONT (19/18)**: Einen Prozess anhalten und fortsetzen.
</details>

<details>
<summary><strong>8. Wie finden und beenden Sie einen Prozess, der zu viel CPU verbraucht?</strong></summary>
<br>

1. Prozess identifizieren: `top -o %CPU` oder `ps aux --sort=-%cpu | head -10`.
2. Details abrufen: `ls -l /proc/<pid>/exe` um die tatsächliche Binary zu sehen.
3. Prüfen, was er tut: `strace -p <pid>` für Systemaufrufe, `lsof -p <pid>` für offene Dateien.
4. Sanftes Beenden: `kill <pid>` (SIGTERM) — Aufräumen erlauben.
5. Erzwungenes Beenden: `kill -9 <pid>` (SIGKILL) — nur wenn SIGTERM fehlschlägt.
6. Wiederholung verhindern: Wenn von systemd verwaltet, `CPUQuota=50%` in der Service-Unit-Datei setzen.
</details>

## Systemd & Dienste

<details>
<summary><strong>9. Was ist systemd und wie unterscheidet es sich von SysVinit?</strong></summary>
<br>

**SysVinit**: Sequentieller Bootprozess mit Shell-Skripten in `/etc/init.d/`. Dienste starten nacheinander in einem definierten Runlevel. Langsame Bootzeiten. Einfach, aber eingeschränkte Abhängigkeitsverwaltung.

**systemd**: Paralleler Bootprozess mit Unit-Dateien. Unterstützt Abhängigkeiten, Socket-Aktivierung, On-Demand-Dienststart, cgroups für Ressourcenkontrolle und journald für Protokollierung. Deutlich schnellerer Boot. Verwaltet Dienste, Timer, Mounts, Sockets und Targets.

systemd ist das Standard-Init-System auf RHEL, Ubuntu, Debian, Fedora, SUSE und Arch.
</details>

<details>
<summary><strong>10. Wie erstellen Sie einen benutzerdefinierten systemd-Dienst?</strong></summary>
<br>

Erstellen Sie eine Unit-Datei in `/etc/systemd/system/myapp.service`:

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

Dann: `sudo systemctl daemon-reload && sudo systemctl enable --now myapp`.

Wichtige `Type`-Werte: `simple` (Standard, Hauptprozess läuft im Vordergrund), `forking` (Prozess forkt in den Hintergrund, benötigt `PIDFile`), `oneshot` (läuft einmal und beendet sich), `notify` (Prozess signalisiert Bereitschaft über sd_notify).
</details>

<details>
<summary><strong>11. Wie analysieren Sie die Boot-Performance mit systemd?</strong></summary>
<br>

- `systemd-analyze` — Gesamtbootzeit.
- `systemd-analyze blame` — Liste der Dienste sortiert nach Startzeit.
- `systemd-analyze critical-chain` — Baum des kritischen Bootpfads.
- `systemd-analyze plot > boot.svg` — eine visuelle Zeitleiste der Bootsequenz generieren.
- `journalctl -b -p err` — Fehler des aktuellen Boots.

Um den Boot zu beschleunigen: Unnötige Dienste deaktivieren (`systemctl disable`), Dienste auf Socket-Aktivierung umstellen (Start bei Bedarf) und langsame Dienste aus der Blame-Ausgabe identifizieren.
</details>

## Netzwerk

<details>
<summary><strong>12. Erklären Sie den TCP-Drei-Wege-Handshake.</strong></summary>
<br>

1. **SYN**: Der Client sendet ein SYN-Paket an den Server mit einer initialen Sequenznummer.
2. **SYN-ACK**: Der Server antwortet mit SYN-ACK, bestätigt das SYN des Clients und sendet seine eigene Sequenznummer.
3. **ACK**: Der Client sendet ein ACK, das die Sequenznummer des Servers bestätigt. Die Verbindung ist aufgebaut.

Der Abbau verwendet einen Vier-Wege-Handshake: FIN → ACK → FIN → ACK (jede Seite schließt unabhängig ihre Hälfte der Verbindung).

Debugging mit: `ss -tuln` (lauschende Ports), `ss -tulnp` (mit Prozessnamen), `tcpdump -i eth0 port 80` (Paketaufzeichnung).
</details>

<details>
<summary><strong>13. Was ist der Unterschied zwischen TCP und UDP?</strong></summary>
<br>

- **TCP** (Transmission Control Protocol): Verbindungsorientiert, zuverlässig, geordnete Zustellung. Verwendet Handshake, Bestätigungen, Neuübertragungen. Höherer Overhead. Verwendet für HTTP, SSH, FTP, Datenbanken.
- **UDP** (User Datagram Protocol): Verbindungslos, unzuverlässig, keine garantierte Reihenfolge. Kein Handshake, keine Bestätigungen. Geringerer Overhead, niedrigere Latenz. Verwendet für DNS, DHCP, VoIP, Streaming, Gaming.

Wichtige Erkenntnis: "Unzuverlässig" bedeutet nicht schlecht — es bedeutet, dass die Anwendung die Zuverlässigkeit bei Bedarf selbst handhabt. DNS verwendet UDP, weil Abfragen klein und schnell sind; wenn eine Antwort verloren geht, sendet der Client sie einfach erneut.
</details>

<details>
<summary><strong>14. Ein Server kann eine externe IP nicht erreichen. Wie gehen Sie bei der Fehlerbehebung vor?</strong></summary>
<br>

Schicht-für-Schicht-Ansatz:
1. **L1 - Physisch**: `ip link show` — ist die Schnittstelle aktiv?
2. **L2 - Sicherungsschicht**: `ip neighbor show` — ist die ARP-Tabelle gefüllt?
3. **L3 - Netzwerk**: `ip route show` — gibt es ein Standard-Gateway? `ping <gateway>` — können Sie es erreichen?
4. **L3 - Extern**: `ping 8.8.8.8` — können Sie das Internet per IP erreichen?
5. **L7 - DNS**: `nslookup google.com` — funktioniert die DNS-Auflösung? Prüfen Sie `/etc/resolv.conf`.
6. **Firewall**: `iptables -L -n` oder `nft list ruleset` — sind ausgehende Verbindungen blockiert?
7. **Route-Verfolgung**: `traceroute 8.8.8.8` — wo bricht der Pfad ab?
</details>

## Speicher & Dateisysteme

<details>
<summary><strong>15. Was ist ein Inode?</strong></summary>
<br>

Ein Inode ist eine Datenstruktur, die Metadaten über eine Datei speichert: Berechtigungen, Eigentümerschaft, Größe, Zeitstempel und Zeiger auf die Datenblöcke auf der Festplatte. Jede Datei und jedes Verzeichnis hat einen Inode.

Entscheidend ist, dass der **Dateiname NICHT im Inode gespeichert** wird — er wird im Verzeichniseintrag gespeichert, der einen Namen einer Inode-Nummer zuordnet. Deshalb funktionieren Hardlinks: Mehrere Verzeichniseinträge können auf denselben Inode zeigen.

Wenn die Inodes ausgehen (auch bei freiem Speicherplatz), können keine neuen Dateien erstellt werden. Prüfen Sie mit `df -i`. Häufige Ursache: Millionen kleiner Dateien (Mail-Warteschlangen, Cache-Verzeichnisse).
</details>

<details>
<summary><strong>16. Wie erweitern Sie ein LVM Logical Volume ohne Ausfallzeit?</strong></summary>
<br>

1. Verfügbaren Platz prüfen: `vgdisplay` — nach freien PE (Physical Extents) suchen.
2. Wenn kein freier Platz vorhanden ist, eine neue physische Festplatte hinzufügen: `pvcreate /dev/sdb && vgextend myvg /dev/sdb`.
3. Das Logical Volume erweitern: `lvextend -L +10G /dev/myvg/mylv`.
4. Das Dateisystem vergrößern (online für ext4/XFS):
   - ext4: `resize2fs /dev/myvg/mylv`
   - XFS: `xfs_growfs /mountpoint`

Kein Aushängen nötig. Keine Ausfallzeit. Dies ist einer der Hauptvorteile von LVM gegenüber rohen Partitionen.
</details>

## Sicherheit & Härtung

<details>
<summary><strong>17. Was ist der Unterschied zwischen su, sudo und sudoers?</strong></summary>
<br>

- **su** (switch user): Wechselt vollständig zu einem anderen Benutzer. `su -` lädt die Umgebung des Zielbenutzers. Erfordert das Passwort des Zielbenutzers.
- **sudo** (superuser do): Führt einen einzelnen Befehl als anderer Benutzer (normalerweise root) aus. Erfordert das Passwort des **Aufrufers**. Bietet Audit-Protokollierung, wer was ausgeführt hat.
- **sudoers** (`/etc/sudoers`): Konfigurationsdatei, die definiert, wer sudo verwenden darf und welche Befehle ausgeführt werden dürfen. Sicher bearbeitet mit `visudo` (Syntaxvalidierung).

Best Practice: Direkten Root-Login deaktivieren (`PermitRootLogin no` in sshd_config). Stattdessen Administratoren sudo-Zugang geben — es bietet Nachvollziehbarkeit (protokolliert wer was getan hat) und granulare Kontrolle.
</details>

<details>
<summary><strong>18. Wie härten Sie einen SSH-Server?</strong></summary>
<br>

Wesentliche Änderungen in `/etc/ssh/sshd_config`:
- `PermitRootLogin no` — direkten Root-Login verhindern.
- `PasswordAuthentication no` — schlüsselbasierte Authentifizierung erzwingen.
- `PubkeyAuthentication yes` — SSH-Schlüssel aktivieren.
- `Port 2222` — vom Standardport wegwechseln (reduziert automatisierte Scans).
- `MaxAuthTries 3` — Authentifizierungsversuche begrenzen.
- `AllowUsers deploy admin` — bestimmte Benutzer auf die Whitelist setzen.
- `ClientAliveInterval 300` — inaktive Sitzungen trennen.
- `fail2ban` installieren — IPs nach fehlgeschlagenen Anmeldeversuchen automatisch sperren.
</details>

## Scripting & Automatisierung

<details>
<summary><strong>19. Was ist der Unterschied zwischen $?, $$, $! und $@ in Bash?</strong></summary>
<br>

- **$?** — Exit-Status des letzten Befehls (0 = Erfolg, ungleich Null = Fehler).
- **$$** — PID der aktuellen Shell.
- **$!** — PID des letzten Hintergrundprozesses.
- **$@** — Alle an das Skript übergebenen Argumente (jedes als separates Wort).
- **$#** — Anzahl der Argumente.
- **$0** — Name des Skripts selbst.
- **$1, $2, ...** — Einzelne Positionsargumente.

Gängiges Muster: `command && echo "success" || echo "fail"` verwendet `$?` implizit.
</details>

<details>
<summary><strong>20. Schreiben Sie einen Einzeiler, um alle Dateien größer als 100 MB zu finden, die in den letzten 7 Tagen geändert wurden.</strong></summary>
<br>

```bash
find / -type f -size +100M -mtime -7 -exec ls -lh {} \; 2>/dev/null
```

Aufschlüsselung:
- `find /` — Suche ab Root.
- `-type f` — nur Dateien (keine Verzeichnisse).
- `-size +100M` — größer als 100 Megabyte.
- `-mtime -7` — innerhalb der letzten 7 Tage geändert.
- `-exec ls -lh {} \;` — menschenlesbare Größe für jedes Ergebnis anzeigen.
- `2>/dev/null` — Berechtigungsfehler unterdrücken.

Alternative mit Sortierung: `find / -type f -size +100M -mtime -7 -printf '%s %p\n' 2>/dev/null | sort -rn | head -20`.
</details>
