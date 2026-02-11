---
title: "Top 20 Docker-Interviewfragen und Antworten (Ausgabe 2026)"
description: "Bestehe dein Senior DevOps Interview mit diesen 20 fortgeschrittenen Docker-Fragen zu Containern, Images, Netzwerken, Volumes, Docker Compose und Best Practices für die Produktion."
date: 2026-02-11
tags: ["docker", "interview", "devops", "containers"]
keywords: ["Docker Interviewfragen", "Senior DevOps Interview", "Containerisierungsfragen", "Docker Interviewantworten", "Docker Compose Interview", "Dockerfile Best Practices", "Container-Orchestrierung Interview", "Docker Netzwerkfragen", "DevOps Ingenieur Interview", "Docker Produktionsfragen"]
draft: false
schema_json: >
  {
    "@context": "https://schema.org",
    "@type": "TechArticle",
    "name": "Top 20 Docker-Interviewfragen und Antworten (Ausgabe 2026)",
    "description": "Fortgeschrittene Docker-Interviewfragen für Senior DevOps-Rollen zu Containern, Images, Netzwerken und Best Practices für die Produktion.",
    "proficiencyLevel": "Advanced",
    "inLanguage": "de"
  }
---

## Systeminitialisierung

Docker ist zu einer unverzichtbaren Fähigkeit für jede DevOps-, SRE- oder Backend-Engineering-Rolle geworden. Interviewer auf Senior-Level erwarten, dass du über `docker run` hinausgehst — sie wollen sehen, dass du Image-Layering, Netzwerk-Interna, Sicherheitshärtung und produktionsreife Orchestrierungsmuster verstehst. Dieser Leitfaden enthält die 20 am häufigsten gestellten Fragen in Senior- und Lead-Level-Interviews mit detaillierten Antworten, die Tiefe demonstrieren.

**Brauchst du eine schnelle Befehlsauffrischung vor deinem Interview?** Speichere unser [Docker Captain's Log Cheatsheet](/cheatsheets/docker-container-commands/) als Lesezeichen.

---

## Kernkonzepte

<details>
<summary><strong>1. Was ist der Unterschied zwischen einem Container und einer virtuellen Maschine?</strong></summary>
<br>

Eine **virtuelle Maschine** führt ein vollständiges Gastbetriebssystem auf einem Hypervisor aus, einschließlich eigenem Kernel, Treibern und Systembibliotheken. Jede VM ist vollständig isoliert, verbraucht aber erhebliche Ressourcen (GBs RAM, Minuten zum Booten).

Ein **Container** teilt den Kernel des Host-Betriebssystems und isoliert Prozesse mittels Linux-Namespaces und cgroups. Er enthält nur die Anwendung und ihre Abhängigkeiten — keinen separaten Kernel. Das macht Container leichtgewichtig (MBs), schnell startbar (Millisekunden) und hochportabel.

Hauptunterschied: VMs virtualisieren die **Hardware**, Container virtualisieren das **Betriebssystem**.
</details>

<details>
<summary><strong>2. Was sind Docker-Image-Layer und wie funktionieren sie?</strong></summary>
<br>

Ein Docker-Image besteht aus einer Serie von **schreibgeschützten Layern**. Jede Anweisung im Dockerfile (`FROM`, `RUN`, `COPY`, etc.) erstellt einen neuen Layer. Layer werden mithilfe eines Union-Dateisystems (wie OverlayFS) übereinander gestapelt.

Wenn ein Container läuft, fügt Docker einen dünnen **beschreibbaren Layer** obenauf hinzu (den Container-Layer). Änderungen zur Laufzeit betreffen nur diesen beschreibbaren Layer — die darunterliegenden Image-Layer bleiben unverändert.

Diese Architektur ermöglicht:
- **Caching**: Wenn sich ein Layer nicht geändert hat, verwendet Docker ihn aus dem Cache beim Bauen.
- **Teilen**: Mehrere Container aus demselben Image teilen sich die schreibgeschützten Layer und sparen Speicherplatz.
- **Effizienz**: Nur geänderte Layer müssen zu Registries heruntergeladen oder hochgeladen werden.
</details>

<details>
<summary><strong>3. Was ist der Unterschied zwischen CMD und ENTRYPOINT in einem Dockerfile?</strong></summary>
<br>

Beide definieren, was beim Start eines Containers ausgeführt wird, verhalten sich aber unterschiedlich:

- **CMD** stellt Standardargumente bereit, die zur Laufzeit vollständig überschrieben werden können. Wenn du `docker run myimage /bin/bash` ausführst, wird CMD ersetzt.
- **ENTRYPOINT** definiert die Hauptanwendung, die immer ausgeführt wird. Laufzeitargumente werden angehängt, nicht ersetzt.

Best Practice: Verwende `ENTRYPOINT` für den Hauptprozess und `CMD` für Standardargumente:

```dockerfile
ENTRYPOINT ["python", "app.py"]
CMD ["--port", "8080"]
```

`docker run myimage --port 3000` führt `python app.py --port 3000` aus.
</details>

<details>
<summary><strong>4. Was ist ein Multi-Stage-Build und warum ist er wichtig?</strong></summary>
<br>

Ein Multi-Stage-Build verwendet mehrere `FROM`-Anweisungen in einem einzelnen Dockerfile. Jedes `FROM` startet eine neue Build-Phase, und du kannst selektiv Artefakte von einer Phase in eine andere kopieren.

```dockerfile
# Stage 1: Build
FROM golang:1.21 AS builder
WORKDIR /app
COPY . .
RUN go build -o myapp

# Stage 2: Run (minimal image)
FROM alpine:3.18
COPY --from=builder /app/myapp /usr/local/bin/
CMD ["myapp"]
```

Dies erzeugt ein finales Image, das nur das kompilierte Binary enthält — keine Build-Tools, kein Quellcode, keine Zwischendateien. Das Ergebnis ist ein dramatisch kleineres Image (oft 10-100x kleiner) mit einer reduzierten Angriffsfläche.
</details>

<details>
<summary><strong>5. Was ist der Unterschied zwischen COPY und ADD in einem Dockerfile?</strong></summary>
<br>

Beide kopieren Dateien aus dem Build-Kontext ins Image, aber `ADD` hat zusätzliche Funktionen:
- `ADD` kann lokale `.tar`-Archive automatisch entpacken.
- `ADD` kann Dateien von URLs herunterladen.

Docker-Best-Practices empfehlen jedoch, in fast allen Fällen `COPY` zu verwenden, da es explizit und vorhersehbar ist. Verwende `ADD` nur, wenn du speziell Tar-Extraktion benötigst. Verwende niemals `ADD` zum Herunterladen von Dateien — verwende stattdessen `RUN curl` oder `RUN wget`, damit der Download-Layer korrekt gecacht werden kann.
</details>

## Netzwerk

<details>
<summary><strong>6. Erkläre Dockers Netzwerkmodi (bridge, host, none, overlay).</strong></summary>
<br>

- **Bridge** (Standard): Erstellt ein privates internes Netzwerk auf dem Host. Container im selben Bridge können über IP oder Containernamen kommunizieren. Traffic nach außen erfordert Port-Mapping (`-p`).
- **Host**: Entfernt die Netzwerkisolierung. Der Container teilt den Netzwerkstack des Hosts direkt. Kein Port-Mapping nötig, aber auch keine Isolation. Nützlich für performancekritische Anwendungen.
- **None**: Kein Netzwerk. Der Container hat nur ein Loopback-Interface. Verwendet für Batch-Jobs oder sicherheitskritische Workloads.
- **Overlay**: Erstreckt sich über mehrere Docker-Hosts (verwendet in Swarm/Kubernetes). Container auf verschiedenen Maschinen können kommunizieren, als wären sie im selben Netzwerk, mittels VXLAN-Tunneling.
</details>

<details>
<summary><strong>7. Wie funktioniert die Container-zu-Container-Kommunikation?</strong></summary>
<br>

In einem benutzerdefinierten Bridge-Netzwerk können Container einander **über den Containernamen** erreichen, mithilfe des eingebauten DNS-Resolvers von Docker. Der DNS-Server läuft unter `127.0.0.11` in jedem Container.

Im Standard-Bridge-Netzwerk ist die DNS-Auflösung **nicht** verfügbar — Container können nur über IP-Adressen kommunizieren, was unzuverlässig ist, da IPs dynamisch zugewiesen werden.

Best Practice: Erstelle immer ein benutzerdefiniertes Bridge-Netzwerk (`docker network create mynet`) und verbinde Container damit. Verlasse dich nie auf das Standard-Bridge für die Inter-Container-Kommunikation.
</details>

<details>
<summary><strong>8. Was ist der Unterschied zwischen EXPOSE und dem Veröffentlichen eines Ports?</strong></summary>
<br>

`EXPOSE` in einem Dockerfile ist reine **Dokumentation** — es teilt jedem, der das Dockerfile liest, mit, dass die Anwendung auf einem bestimmten Port lauscht. Es öffnet oder mappt den Port NICHT tatsächlich.

Das Veröffentlichen eines Ports (`-p 8080:80`) erstellt tatsächlich eine Netzwerkregel, die einen Host-Port auf einen Container-Port mappt und den Dienst von außerhalb des Containers zugänglich macht.

Du kannst Ports veröffentlichen, die nicht in der `EXPOSE`-Direktive stehen, und `EXPOSE` allein bewirkt nichts ohne `-p`.
</details>

## Volumes und Speicher

<details>
<summary><strong>9. Was sind die drei Arten von Docker-Mounts?</strong></summary>
<br>

1. **Volumes** (`docker volume create`): Von Docker verwaltet, gespeichert in `/var/lib/docker/volumes/`. Ideal für persistente Daten (Datenbanken). Überlebt die Container-Entfernung. Portabel zwischen Hosts.
2. **Bind Mounts** (`-v /host/path:/container/path`): Mappt ein bestimmtes Host-Verzeichnis in den Container. Der Host-Pfad muss existieren. Ideal für Entwicklung (Live-Code-Reloading). Nicht portabel.
3. **tmpfs Mounts** (`--tmpfs /tmp`): Nur im Arbeitsspeicher des Hosts gespeichert. Wird nie auf die Festplatte geschrieben. Ideal für sensible Daten, die nicht persistiert werden sollen (Geheimnisse, Session-Tokens).
</details>

<details>
<summary><strong>10. Wie persistiert man Daten eines Datenbank-Containers?</strong></summary>
<br>

Verwende ein **benanntes Volume**, das im Datenverzeichnis der Datenbank gemountet wird:

```bash
docker volume create pgdata
docker run -d -v pgdata:/var/lib/postgresql/data postgres:16
```

Die Daten überleben Container-Neustarts und -Entfernungen. Beim Upgrade der Datenbankversion stoppst du den alten Container, startest einen neuen mit demselben Volume und lässt die neue Version die Datenmigration durchführen.

Verwende niemals Bind Mounts für Produktionsdatenbanken — Volumes haben bessere I/O-Performance und werden vom Storage-Treiber von Docker verwaltet.
</details>

## Sicherheit

<details>
<summary><strong>11. Wie sichert man einen Docker-Container in der Produktion ab?</strong></summary>
<br>

Wichtige Härtungspraktiken:
- **Als Nicht-Root ausführen**: Verwende die `USER`-Direktive im Dockerfile. Führe Anwendungsprozesse niemals als Root aus.
- **Minimale Basis-Images verwenden**: `alpine`, `distroless` oder `scratch` statt `ubuntu`.
- **Capabilities entfernen**: Verwende `--cap-drop ALL --cap-add <nur-benötigte>`.
- **Schreibgeschütztes Dateisystem**: Verwende `--read-only` und mounte nur bestimmte beschreibbare Pfade.
- **Keine neuen Privilegien**: Verwende `--security-opt=no-new-privileges`.
- **Images scannen**: Verwende `docker scout`, Trivy oder Snyk, um Schwachstellen in Basis-Images und Abhängigkeiten zu erkennen.
- **Images signieren**: Verwende Docker Content Trust (`DOCKER_CONTENT_TRUST=1`), um die Authentizität von Images zu überprüfen.
- **Ressourcen begrenzen**: Verwende `--memory`, `--cpus`, um Ressourcenerschöpfung zu verhindern.
</details>

<details>
<summary><strong>12. Was ist der Rootless-Modus von Docker?</strong></summary>
<br>

Der Rootless-Modus von Docker führt den Docker-Daemon und Container vollständig innerhalb eines Benutzer-Namespaces aus, ohne Root-Privilegien auf dem Host zu benötigen. Dies eliminiert das Hauptsicherheitsbedenken bei Docker: Der Daemon läuft als Root, und ein Container-Ausbruch bedeutet Root-Zugriff auf den Host.

Im Rootless-Modus erhält ein Angreifer selbst bei einem Container-Ausbruch nur die Privilegien des unprivilegierten Benutzers, der Docker ausführt. Der Kompromiss ist, dass einige Funktionen (wie das Binden an Ports unter 1024) zusätzliche Konfiguration erfordern.
</details>

## Docker Compose und Orchestrierung

<details>
<summary><strong>13. Was ist der Unterschied zwischen docker-compose up und docker-compose run?</strong></summary>
<br>

- `docker compose up`: Startet **alle** in `docker-compose.yml` definierten Services, erstellt Netzwerke/Volumes und respektiert die `depends_on`-Reihenfolge. Typischerweise verwendet, um den gesamten Stack hochzufahren.
- `docker compose run <service> <befehl>`: Startet einen **einzelnen** Service mit einem einmaligen Befehl. Startet standardmäßig keine abhängigen Services (verwende `--service-ports` zum Port-Mapping, `--rm` zum Aufräumen). Verwendet für Migrationen, Tests oder Admin-Aufgaben.
</details>

<details>
<summary><strong>14. Wie funktioniert depends_on und was sind seine Einschränkungen?</strong></summary>
<br>

`depends_on` steuert die **Startreihenfolge** — es stellt sicher, dass Service A vor Service B startet. Es wartet jedoch nur darauf, dass der Container **startet**, nicht darauf, dass die Anwendung darin **bereit** ist.

Beispiel: Ein Datenbank-Container könnte in Sekunden starten, aber PostgreSQL braucht zusätzliche Zeit zur Initialisierung. Dein App-Container startet und schlägt sofort bei der Verbindung fehl.

Lösung: Verwende `depends_on` mit einer `condition` und einem Health Check:

```yaml
services:
  db:
    image: postgres:16
    healthcheck:
      test: ["CMD-SHELL", "pg_isready -U user"]
      interval: 5s
      timeout: 5s
      retries: 5
  app:
    depends_on:
      db:
        condition: service_healthy
```
</details>

<details>
<summary><strong>15. Wann würdest du Docker Swarm gegenüber Kubernetes wählen?</strong></summary>
<br>

**Docker Swarm**: In Docker integriert, keine zusätzliche Einrichtung. Ideal für kleine bis mittlere Deployments, bei denen Einfachheit zählt. Verwendet dieselben Docker-Compose-Dateien. Begrenztes Ökosystem und Community im Vergleich zu Kubernetes. Geeignet für Teams ohne dedizierte Plattform-Ingenieure.

**Kubernetes**: Industriestandard für Container-Orchestrierung im großen Maßstab. Unterstützt Auto-Scaling, Rolling Updates, Service Mesh, Custom Resource Definitions und ein riesiges Ökosystem (Helm, Istio, ArgoCD). Höhere Komplexität und Lernkurve. Erforderlich für großangelegte, Multi-Team- und Multi-Cloud-Deployments.

Faustregel: Wenn du weniger als 20 Services und ein kleines Team hast, reicht Swarm aus. Darüber hinaus lohnt sich die Investition in Kubernetes.
</details>

## Produktion und Fehlerbehebung

<details>
<summary><strong>16. Wie reduziert man die Größe eines Docker-Images?</strong></summary>
<br>

1. **Multi-Stage-Builds verwenden** — Build-Tools aus dem finalen Image heraushalten.
2. **Minimale Basis-Images verwenden** — `alpine` (~5MB) statt `ubuntu` (~75MB).
3. **RUN-Befehle kombinieren** — jedes `RUN` erstellt einen Layer. Befehle mit `&&` verketten und im selben Layer aufräumen.
4. **.dockerignore verwenden** — `node_modules`, `.git`, Testdateien, Dokumentation aus dem Build-Kontext ausschließen.
5. **Layer nach Änderungshäufigkeit ordnen** — selten geänderte Layer (Abhängigkeiten) vor häufig geänderten Layern (Quellcode) platzieren, um Cache-Treffer zu maximieren.
</details>

<details>
<summary><strong>17. Ein Container startet ständig neu. Wie debuggst du ihn?</strong></summary>
<br>

Schrittweiser Ansatz:
1. `docker ps -a` — Exit-Code prüfen. Exit-Code 137 = OOM-Kill. Exit-Code 1 = Anwendungsfehler.
2. `docker logs <container>` — Anwendungslogs auf Stack-Traces oder Fehlermeldungen prüfen.
3. `docker inspect <container>` — `State.OOMKilled`, Ressourcenlimits und Umgebungsvariablen prüfen.
4. `docker run -it --entrypoint /bin/sh <image>` — interaktive Shell starten, um die Umgebung manuell zu debuggen.
5. `docker stats` — prüfen, ob der Container Speicher- oder CPU-Limits erreicht.
6. `docker events` prüfen — nach Kill-Signalen oder OOM-Events vom Daemon suchen.
</details>

<details>
<summary><strong>18. Was ist der Unterschied zwischen docker stop und docker kill?</strong></summary>
<br>

- `docker stop` sendet **SIGTERM** an den Hauptprozess (PID 1) und wartet eine Gnadenfrist ab (Standard 10 Sekunden). Wenn der Prozess nicht beendet wird, sendet Docker SIGKILL. Dies ermöglicht der Anwendung ein graceful Shutdown (Verbindungen schließen, Buffer leeren, Zustand speichern).
- `docker kill` sendet **SIGKILL** sofort. Der Prozess wird ohne jede Möglichkeit zum Aufräumen beendet. Nur verwenden, wenn ein Container nicht mehr reagiert.

Best Practice: Verwende in der Produktion immer `docker stop`. Stelle sicher, dass deine Anwendung SIGTERM korrekt behandelt.
</details>

<details>
<summary><strong>19. Wie handhabt man Geheimnisse in Docker?</strong></summary>
<br>

Geheimnisse **niemals** in Images einbetten (ENV im Dockerfile, COPY von .env-Dateien). Sie bleiben in Image-Layern erhalten und sind mit `docker history` sichtbar.

Ansätze nach Reifegrad:
- **Grundlegend**: Geheimnisse via `--env-file` zur Laufzeit übergeben (Datei nicht im Image enthalten).
- **Besser**: Docker Swarm Secrets oder Kubernetes Secrets verwenden (als Dateien gemountet, nicht als Umgebungsvariablen).
- **Optimal**: Externen Secrets-Manager verwenden (HashiCorp Vault, AWS Secrets Manager, Azure Key Vault) und Geheimnisse zur Laufzeit via Sidecar oder Init-Container injizieren.
</details>

<details>
<summary><strong>20. Was ist ein Docker Health Check und warum ist er entscheidend?</strong></summary>
<br>

Ein Health Check ist ein Befehl, den Docker periodisch innerhalb des Containers ausführt, um zu überprüfen, ob die Anwendung tatsächlich funktioniert — nicht nur, dass der Prozess läuft.

```dockerfile
HEALTHCHECK --interval=30s --timeout=5s --retries=3 \
  CMD curl -f http://localhost:3000/health || exit 1
```

Ohne Health Check weiß Docker nur, ob der Prozess lebt (PID existiert). Mit einem Health Check weiß Docker, ob die Anwendung **gesund** ist (auf Anfragen antwortet). Dies ist entscheidend für:
- **Load Balancer**: Traffic nur an gesunde Container weiterleiten.
- **Orchestratoren**: Ungesunde Container automatisch neu starten.
- **depends_on**: Auf tatsächliche Bereitschaft warten, nicht nur auf den Prozessstart.
</details>
