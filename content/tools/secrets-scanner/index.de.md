---
title: "Secrets Scanner: API-Keys im Code finden"
description: "Fügen Sie eine .env, Konfigurationsdatei oder Code ein und finden Sie geleakte API-Keys, Tokens, private Schlüssel und Passwörter vor dem Commit – lokal."
intro: "**SafeEnv** durchsucht Text nach geleakten Zugangsdaten: AWS-, GitHub-, Stripe-, OpenAI- und Slack-Keys, private Schlüsselblöcke, Passwörter in Verbindungs-URLs und Werte mit hoher Entropie neben Namen wie `SECRET` oder `TOKEN`. Einfügen oder Datei ablegen – der Scan läuft komplett in Ihrem Browser."
date: 2026-07-05
lastmod: 2026-10-24
reviewed: false
keywords: ["secrets scanner", "api key im code finden", "env datei scannen", "hardcodierte passwörter finden", "zugangsdaten leak erkennen", "github token leak", "secret detection online", "api key geleakt"]
tags: ["sicherheit", "devsecops", "secrets", "tool"]
app_category: "DeveloperApplication"
tool_file: "/tools/secrets-scanner/"
tool_title: "SafeEnv Secrets Scanner"
tool_height: 1000
tool_sandbox: "allow-scripts allow-same-origin"
tool_allow: "clipboard-write"
howto:
  - "Fügen Sie den Inhalt einer `.env`, `docker-compose.yml`, CI-Konfiguration, Terraform-Datei oder eines Code-Ausschnitts ein, oder nutzen Sie **Scan a file…** bzw. ziehen Sie eine Datei auf das Feld."
  - "Klicken Sie auf **Scan for secrets**. Eine typische Konfigurationsdatei ist in wenigen Millisekunden durchsucht."
  - "Lesen Sie die Übersichts-Chips (critical, high, medium, low, info) und die Funde, sortiert nach Schweregrad und dann nach Zeilennummer."
  - "Jeder Fund zeigt die zutreffende Regel, die Zeile, einen maskierten Wert (nur die ersten und letzten vier Zeichen) und was zu tun ist."
  - "Beheben Sie zuerst die kritischen Funde: Zugangsdaten rotieren, aus Datei und Git-Historie entfernen und aus einem Secret Manager oder einer Umgebungsvariable laden. **Copy report** liefert eine Textzusammenfassung für ein Ticket."
faq:
  - q: "Ist es sicher, echte Secrets in diesen Scanner einzufügen?"
    a: "Der Scanner ist JavaScript, das in dieser Seite läuft, und stellt mit Ihrem Text keine Netzwerkanfragen – nichts erreicht unsere Server. Angezeigt werden maskierte Werte, nie vollständige Secrets. Trotzdem gilt: Finden Sie einen echten Produktionsschlüssel, betrachten Sie ihn als kompromittiert und rotieren Sie ihn."
  - q: "Welche Arten von Secrets erkennt er?"
    a: "Zwanzig konkrete Formate, darunter AWS Access Key IDs und Secret Keys, GitHub- und GitLab-Tokens, Stripe-Live- und Test-Keys, Google-API-Keys, OpenAI- und Anthropic-API-Keys, Slack-Tokens und -Webhooks, SendGrid-, npm-, PyPI-, Telegram-Bot- und Twilio-Keys, JSON Web Tokens, private Schlüsselblöcke und Zugangsdaten in Datenbank- oder HTTP-URLs. Ein zweiter Durchlauf markiert Werte mit hoher Entropie und hartcodierte Passwörter in jeder `KEY=VALUE`-Zeile."
  - q: "Warum wird ein Wert als „high entropy“ markiert?"
    a: "Zufällig aussehende Zeichenketten sind genau das, wie generierte Secrets aussehen. Der Scanner berechnet die Shannon-Entropie jedes Werts ab 20 Zeichen und markiert ihn ab 4,3 Bit pro Zeichen. Werte neben Namen mit secret, token, password, key oder auth werden höher eingestuft. Auch Hashes, UUIDs und Build-IDs können das auslösen – prüfen Sie also den Kontext."
  - q: "Was tun, wenn ein Secret in Git committet wurde?"
    a: "Die Zeile in einem neuen Commit zu löschen reicht nicht: Das Secret bleibt in der Historie und in jedem Klon. Rotieren oder widerrufen Sie zuerst die Zugangsdaten, schreiben Sie dann die Historie mit `git filter-repo` oder BFG Repo-Cleaner um, pushen Sie mit Force und bitten Sie Mitwirkende, neu zu klonen. Die Rotation ist der Schritt, der Sie wirklich schützt."
  - q: "Ersetzt er Tools wie Gitleaks oder das Secret Scanning von GitHub?"
    a: "Nein, er ergänzt sie. Nutzen Sie für jeden Commit einen Pre-Commit-Hook oder einen CI-Scanner und die Push Protection von GitHub in Ihren Repositories. SafeEnv ist für die Momente dazwischen: einen Ausschnitt prüfen, bevor Sie ihn in einen Chat, ein Ticket oder einen KI-Assistenten einfügen, oder eine zugeschickte Konfiguration durchsehen."
  - q: "Warum werden Platzhalter als Info gelistet?"
    a: "Zeilen wie `API_KEY=your-api-key-here` oder `PASSWORD=${DB_PASSWORD}` haben die Form eines Secrets, sind aber Vorlagen. Der Scanner erkennt gängige Platzhaltermuster (your-, changeme, example, xxx, `${VAR}`, `<value>`) und meldet sie als Info, damit Sie bestätigen können, dass sie Absicht sind."
---

## So funktioniert es

Der Scanner ist eine kleine Regel-Engine ohne Abhängigkeiten. Er durchläuft den Text zweimal.

### Durchlauf 1: bekannte Token-Formate

Zwanzig reguläre Ausdrücke erkennen Formate, die Anbieter öffentlich dokumentieren, meist anhand eines festen Präfixes und der Länge. Einige Beispiele dafür, wonach die Regeln suchen:

| Regel | Erkannte Signatur | Schweregrad |
|---|---|---|
| Privater Schlüsselblock | `-----BEGIN … PRIVATE KEY` (RSA, EC, DSA, OpenSSH, PGP, verschlüsselt) | Kritisch |
| AWS Access Key ID | `AKIA`, `ASIA`, `ABIA` oder `ACCA` gefolgt von 16 Großbuchstaben oder Ziffern | Kritisch |
| AWS Secret Access Key | Ein 40-stelliger Base64-Wert, zugewiesen an einen Namen wie `aws_secret_access_key` | Kritisch |
| GitHub-Token | Präfixe `ghp_`, `gho_`, `ghu_`, `ghs_`, `ghr_` oder `github_pat_` | Kritisch |
| Stripe-Live-Key | Präfixe `sk_live` / `rk_live` | Kritisch |
| OpenAI- / Anthropic-Key | Präfixe `sk-proj-`, `sk-svcacct-`, `sk-ant-` | Kritisch |
| Google-API-Key | `AIza` gefolgt von 35 Zeichen | Hoch |
| Slack-Token / -Webhook | Tokens `xox[baprs]-`, URLs `hooks.slack.com/services/…` | Hoch |
| Zugangsdaten in einer URI | `postgres://user:passwort@host`, ebenso MySQL, MongoDB, Redis, AMQP, FTP und HTTP Basic Auth | Hoch |
| JSON Web Token | Drei Base64URL-Segmente, beginnend mit `eyJ` | Mittel |
| Stripe-Test- / Publishable-Key | `sk_test_`, `pk_live_`, `pk_test_` | Niedrig |

Jeder Treffer speichert die Zeilennummer (gezählt über die vorangehenden Zeilenumbrüche) und eine **maskierte** Fassung des Werts, die nur die ersten und letzten vier Zeichen behält – der Bericht selbst enthält also nie das Secret.

### Durchlauf 2: generische `KEY=VALUE`-Analyse

Zeilen, die keine spezifische Regel erfasst hat, werden als Zuweisungen gelesen – die Syntax von `.env`, YAML und den meisten Konfigurationsformaten (`export`-Präfixe, Anführungszeichen und `#`-Kommentare am Zeilenende werden berücksichtigt). Für jeden Wert ab sechs Zeichen gilt:

1. Sieht er aus wie ein **Platzhalter** (`your-…`, `changeme`, `example`, `xxxx`, `${VAR}`, `<value>`, `true/false/null`), wird er als *Info* gemeldet, wenn der Schlüsselname nach Secret klingt, sonst ignoriert.
2. Werte mit einer URL oder Leerzeichen werden übersprungen, da sie selten für sich genommen Secrets sind.
3. Die **Shannon-Entropie** H = −Σ p·log₂(p) wird über die Zeichenhäufigkeiten berechnet. Ein Wert ab 20 Zeichen mit H ≥ 4,3 Bit pro Zeichen wird als *high entropy* markiert – mit hohem Schweregrad, wenn der Schlüsselname secret, token, passw, pwd, api_key, private, credential oder auth enthält, sonst mittel.
4. Ein Wert mit geringerer Entropie unter einem passwortartigen Namen wird als *hardcoded password* gemeldet.

Die Funde werden nach Schweregrad und dann nach Zeile sortiert. Gespeichert wird nichts: Feld leeren oder Tab schließen, und der Text ist weg.

### Grenzen

Regex-Scans finden *Formate*, keine *Gültigkeit*: Sie können nicht feststellen, ob ein Schlüssel noch aktiv ist. Sie sehen auch keine Secrets, die über mehrere Zeilen verteilt, verschlüsselt oder ungewöhnlich kodiert sind. Deshalb ist das ein schneller Check und kein Ersatz für das Scannen in Ihrer CI-Pipeline.

## Anwendungsfälle

- **Vor dem Teilen eines Ausschnitts.** Prüfen Sie eine Konfiguration oder einen Stacktrace, bevor Sie sie in Slack, ein GitHub-Issue, Stack Overflow oder einen KI-Chatbot einfügen.
- **Vor dem ersten Commit.** Scannen Sie `.env.example`, `docker-compose.yml` und CI-Dateien eines neuen Projekts, damit kein echter Wert durchrutscht.
- **Review eines Pull Requests oder einer Übergabe.** Fügen Sie den Diff der Konfigurationsdateien ein und suchen Sie nach kritischen Funden.
- **Incident Response.** Scannen Sie nach einem vermuteten Leak exportierte Logs oder Konfigurationen, um alle zu rotierenden Zugangsdaten aufzulisten.
- **Gute Gewohnheiten vermitteln.** Die Beispieldatei zeigt einem Team in Sekunden, wie viele Secrets in einer gewöhnlichen `.env` stecken.
