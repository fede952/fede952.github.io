---
title: "SafeEnv: Scanner di Segreti e Chiavi API per File .env"
description: "Analizza i tuoi file .env e frammenti di configurazione alla ricerca di segreti esposti prima del commit — chiavi AWS, token GitHub e Stripe, chiavi private, password negli URL e valori ad alta entropia. 100% nel browser: nulla viene caricato."
date: 2026-07-05
tags: ["security", "developer-tools", "secrets", "privacy"]
keywords: ["scanner file env", "scanner segreti", "controllo chiavi api", "rilevare segreti esposti", "scansione env", "chiavi aws esposte", "git secrets", "scanner segreti lato client", "sicurezza dotenv"]
layout: "tool"
draft: false
tool_file: "/tools/secrets-scanner/"
tool_height: "1150"
schema_json: >
  {"@context": "https://schema.org", "@type": "SoftwareApplication", "name": "SafeEnv — Scanner di Segreti e Chiavi API", "description": "Scanner gratuito lato client che trova chiavi API, token, chiavi private e password esposte in file .env e configurazioni prima del commit.", "applicationCategory": "SecurityApplication", "operatingSystem": "Web", "browserRequirements": "Requires JavaScript", "isAccessibleForFree": true, "offers": {"@type": "Offer", "price": "0", "priceCurrency": "USD"}}
---

## Perché scansionare prima del commit

Basta un `.env` incollato in un repo pubblico: i bot setacciano GitHub e trovano chiavi AWS fresche in **meno di un minuto**. SafeEnv intercetta la fuga prima del commit. Incolla qualsiasi configurazione — `.env`, `docker-compose.yml`, config CI, frammenti di codice — e segnala le credenziali esposte con numero di riga, anteprima mascherata e passi concreti di rimedio.

La scansione avviene interamente nella memoria di questa pagina. Nessun upload, nessun log, nessuna richiesta di rete — l'unico design accettabile per uno strumento in cui incolli segreti reali. Ricarica la pagina e tutto sparisce.

## Cosa rileva

- **Token cloud e API** — chiavi AWS, GitHub, GitLab, Stripe, Google, OpenAI, Anthropic, Slack, SendGrid, npm, PyPI, Telegram, Twilio
- **Chiavi private** — blocchi PEM RSA/EC/OpenSSH/PGP
- **Credenziali negli URL** — stringhe di connessione a database e URL basic-auth con password incorporate
- **Fughe generiche** — password hardcoded e valori ad alta entropia, con riconoscimento dei placeholder per ridurre i falsi positivi

Incolla una configurazione per analizzarla, oppure carica l'esempio per vedere tutti i rilevatori in azione su chiavi finte.
