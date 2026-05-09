---
title: "Nuovo backdoor Linux PamDOORa ruba credenziali SSH tramite PAM"
date: "2026-05-09T08:29:08Z"
original_date: "2026-05-08T08:41:00"
lang: "it"
translationKey: "new-pamdoora-linux-backdoor-steals-ssh-credentials-via-pam"
author: "NewsBot (Validated by Federico Sella)"
description: "Un nuovo backdoor Linux chiamato PamDOORa, venduto su un forum cybercriminale russo per 1.600 dollari, utilizza moduli PAM per fornire accesso SSH persistente con una combinazione di password magica e porta TCP."
original_url: "https://thehackernews.com/2026/05/new-linux-pamdoora-backdoor-uses-pam.html"
source: "The Hacker News"
severity: "High"
target: "Server SSH Linux"
cve: null
cvss: null
kev: null
tags: ["news", "cybersecurity"]
news-categories: ["cybersecurity"]
layout: "news"
draft: false
---

Un nuovo backdoor Linux chiamato PamDOORa, venduto su un forum cybercriminale russo per 1.600 dollari, utilizza moduli PAM per fornire accesso SSH persistente con una combinazione di password magica e porta TCP.

{{< cyber-report severity="High" source="The Hacker News" target="Server SSH Linux" >}}

I ricercatori di cybersecurity hanno scoperto un nuovo backdoor Linux chiamato PamDOORa, pubblicizzato sul forum cybercriminale russo Rehub per 1.600 dollari da un attore di minaccia noto come 'darkworm'. Il backdoor è progettato come un toolkit post-sfruttamento basato su Pluggable Authentication Module (PAM), che consente un accesso SSH persistente attraverso una combinazione di una password magica e una porta TCP specifica.

{{< ad-banner >}}

PamDOORa opera intercettando l'autenticazione SSH tramite moduli PAM dannosi, permettendo agli attaccanti di bypassare le credenziali normali e ottenere accesso non autorizzato. L'uso di moduli PAM rende il backdoor furtivo, poiché si integra nel flusso di autenticazione standard del sistema Linux.

La vendita di tali strumenti sui forum cybercriminali evidenzia la crescente mercificazione di strumenti di attacco sofisticati. Si consiglia alle organizzazioni di monitorare modelli di autenticazione SSH insoliti e di assicurarsi che le configurazioni PAM siano verificate regolarmente.

{{< netrunner-insight >}}

Per gli analisti SOC, rilevare PamDOORa richiede il monitoraggio di connessioni SSH inaspettate su porte non standard e la correlazione con le modifiche ai moduli PAM. I team DevSecOps dovrebbero imporre una gestione rigorosa della configurazione PAM e considerare il monitoraggio dell'integrità dei file per /etc/pam.d/ e le librerie correlate. Questo backdoor sottolinea l'importanza di trattare PAM come un confine di sicurezza critico.

{{< /netrunner-insight >}}

---

**[Leggi l'articolo completo su The Hacker News ›](https://thehackernews.com/2026/05/new-linux-pamdoora-backdoor-uses-pam.html)**
