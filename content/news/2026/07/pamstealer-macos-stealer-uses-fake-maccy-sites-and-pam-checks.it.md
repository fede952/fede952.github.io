---
title: "PamStealer: un ladro macOS che utilizza siti Maccy falsi e controlli PAM"
date: "2026-07-04T09:17:53Z"
original_date: "2026-07-03T08:03:37"
lang: "it"
translationKey: "pamstealer-macos-stealer-uses-fake-maccy-sites-and-pam-checks"
author: "NewsBot (Validated by Federico Sella)"
description: "Jamf Threat Labs scopre PamStealer, un info-stealer per macOS distribuito tramite siti Maccy falsi, che utilizza controlli PAM per rubare password di accesso."
original_url: "https://thehackernews.com/2026/07/pamstealer-uses-fake-maccy-sites-and.html"
source: "The Hacker News"
severity: "High"
target: "utenti macOS"
cve: null
cvss: null
kev: null
tags: ["news", "cybersecurity"]
news-categories: ["cybersecurity"]
layout: "news"
draft: false
---

Jamf Threat Labs scopre PamStealer, un info-stealer per macOS distribuito tramite siti Maccy falsi, che utilizza controlli PAM per rubare password di accesso.

{{< cyber-report severity="High" source="The Hacker News" target="utenti macOS" >}}

I ricercatori di sicurezza informatica di Jamf Threat Labs hanno identificato un nuovo information stealer per macOS chiamato PamStealer. Il malware viene distribuito come file AppleScript compilato (.scpt) che si spaccia per Maccy, un legittimo gestore di appunti open-source. Utilizza una serie di trucchi intelligenti per infettare i sistemi e sottrarre dati sensibili, comprese le password di accesso.

{{< ad-banner >}}

PamStealer prende il nome dalla sua capacità di abusare del framework Pluggable Authentication Module (PAM) su macOS. Intercettando i processi di autenticazione, può catturare le credenziali degli utenti quando accedono o si autenticano per operazioni privilegiate. Il ladro poi esfiltra i dati rubati verso server controllati dagli attaccanti.

La campagna si basa su siti web falsi e ingegneria sociale per indurre gli utenti a scaricare il file .scpt dannoso. Una volta eseguito, il malware esegue controlli PAM per raccogliere le password senza destare sospetti. Le organizzazioni con endpoint macOS dovrebbero monitorare esecuzioni anomale di file .scpt e anomalie relative al PAM.

{{< netrunner-insight >}}

Per gli analisti SOC, ciò evidenzia la necessità di monitorare le esecuzioni di AppleScript compilati e le modifiche al PAM sugli endpoint macOS. I team DevSecOps dovrebbero applicare whitelist delle applicazioni e istruire gli utenti sulla verifica delle fonti del software, specialmente per i gestori di appunti. L'implementazione di regole di rilevamento degli endpoint per l'abuso del PAM può aiutare a individuare questo ladro in fase precoce.

{{< /netrunner-insight >}}

---

**[Leggi l'articolo completo su The Hacker News ›](https://thehackernews.com/2026/07/pamstealer-uses-fake-maccy-sites-and.html)**
