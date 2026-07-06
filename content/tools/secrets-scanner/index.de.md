---
title: "SafeEnv: Secrets- & API-Key-Scanner für .env-Dateien"
description: "Scanne deine .env-Dateien und Konfigurationsausschnitte vor dem Commit auf exponierte Secrets — AWS-Schlüssel, GitHub- und Stripe-Tokens, private Schlüssel, Passwörter in URLs und Werte mit hoher Entropie. 100% im Browser: nichts wird jemals hochgeladen."
date: 2026-07-05
tags: ["security", "developer-tools", "secrets", "privacy"]
keywords: ["env datei scanner", "secret scanner", "api key prüfen", "geleakte secrets finden", "env scannen", "aws key leak", "git secrets", "clientseitiger secret scanner", "dotenv sicherheit"]
layout: "tool"
draft: false
tool_file: "/tools/secrets-scanner/"
tool_height: "1150"
schema_json: >
  {"@context": "https://schema.org", "@type": "SoftwareApplication", "name": "SafeEnv — Secrets- & API-Key-Scanner", "description": "Kostenloser clientseitiger Scanner, der exponierte API-Keys, Tokens, private Schlüssel und Passwörter in .env-Dateien und Configs vor dem Commit findet.", "applicationCategory": "SecurityApplication", "operatingSystem": "Web", "browserRequirements": "Requires JavaScript", "isAccessibleForFree": true, "offers": {"@type": "Offer", "price": "0", "priceCurrency": "USD"}}
---

## Warum vor dem Commit scannen

Eine einzige `.env` in einem öffentlichen Repo genügt: Bots durchsuchen GitHub und finden frische AWS-Schlüssel in **unter einer Minute**. SafeEnv fängt das Leck vor dem Commit ab. Füge eine beliebige Konfiguration ein — `.env`, `docker-compose.yml`, CI-Config, Code-Ausschnitte — und exponierte Zugangsdaten werden mit Zeilennummer, maskierter Vorschau und konkreten Gegenmaßnahmen markiert.

Der Scan läuft vollständig im Speicher dieser Seite. Kein Upload, kein Logging, keine Netzwerkanfrage — das einzig akzeptable Design für ein Tool, in das man echte Secrets einfügt. Seite neu laden, und alles ist weg.

## Was erkannt wird

- **Cloud- & API-Tokens** — AWS-Schlüssel, GitHub, GitLab, Stripe, Google, OpenAI, Anthropic, Slack, SendGrid, npm, PyPI, Telegram, Twilio
- **Private Schlüssel** — PEM-Blöcke (RSA/EC/OpenSSH/PGP)
- **Zugangsdaten in URLs** — Datenbank-Verbindungsstrings und Basic-Auth-URLs mit eingebetteten Passwörtern
- **Generische Lecks** — hartkodierte Passwörter und Werte mit hoher Entropie, mit Platzhalter-Erkennung gegen Fehlalarme

Füge eine Konfiguration zum Scannen ein oder lade das Beispiel, um alle Detektoren an Fake-Schlüsseln auslösen zu sehen.
