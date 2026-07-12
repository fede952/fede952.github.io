---
title: "Falsa registrazione di passkey Microsoft Entra prende di mira gli utenti M365 in una campagna di estorsione dati"
date: "2026-07-12T09:00:42Z"
original_date: "2026-07-10T10:30:20"
lang: "it"
translationKey: "fake-microsoft-entra-passkey-enrollment-targets-m365-users-in-data-extortion-campaign"
slug: "fake-microsoft-entra-passkey-enrollment-targets-m365-users-in-data-extortion-campaign"
author: "NewsBot (Validated by Federico Sella)"
description: "L'attore minaccioso O-UNC-066 utilizza il phishing vocale per indurre gli utenti a registrare una falsa passkey Entra, con l'obiettivo di compromettere gli account Microsoft 365 per estorsione dati."
original_url: "https://thehackernews.com/2026/07/hackers-use-fake-microsoft-entra.html"
source: "The Hacker News"
severity: "High"
target: "utenti Microsoft 365"
cve: null
cvss: null
kev: null
tags: ["news", "cybersecurity"]
news-categories: ["cybersecurity"]
layout: "news"
draft: false
---

L'attore minaccioso O-UNC-066 utilizza il phishing vocale per indurre gli utenti a registrare una falsa passkey Entra, con l'obiettivo di compromettere gli account Microsoft 365 per estorsione dati.

{{< cyber-report severity="High" source="The Hacker News" target="utenti Microsoft 365" >}}

Un attore minaccioso tracciato come O-UNC-066 da Okta è stato osservato mentre conduce attacchi di phishing vocale mirati agli utenti di Microsoft 365 in diversi settori. Gli aggressori si spacciano per richieste di sicurezza legittime per indurre le vittime a registrare una falsa passkey Entra, concedendo così all'avversario accesso non autorizzato ai loro account.

{{< ad-banner >}}

La campagna utilizza un kit di phishing controllato da pannello progettato specificamente per intercettare il processo di registrazione della passkey. Una volta ottenuto l'accesso, l'aggressore mira a compiere estorsione dati, esfiltrare informazioni sensibili e richiedere un riscatto. Gli attacchi evidenziano una tendenza crescente all'uso di canali vocali per bypassare le difese tradizionali basate su email di phishing.

Si consiglia alle organizzazioni di implementare l'autenticazione multifattore (MFA) con chiavi di sicurezza hardware e di educare gli utenti a verificare qualsiasi richiesta di sicurezza non sollecitata tramite canali di comunicazione alternativi. Il monitoraggio di attività anomale di registrazione delle passkey può aiutare a rilevare tempestivamente tali attacchi.

{{< netrunner-insight >}}

Questo attacco sottolinea l'importanza di trattare le richieste di sicurezza vocali con lo stesso scetticismo delle email di phishing. Gli analisti SOC dovrebbero monitorare tentativi insoliti di registrazione delle passkey e assicurarsi che i processi di registrazione MFA richiedano verifica fuori banda. I team DevSecOps dovrebbero considerare l'implementazione di policy di accesso condizionale che limitino la registrazione delle passkey a dispositivi e posizioni fidati.

{{< /netrunner-insight >}}

---

**[Leggi l'articolo completo su The Hacker News ›](https://thehackernews.com/2026/07/hackers-use-fake-microsoft-entra.html)**
