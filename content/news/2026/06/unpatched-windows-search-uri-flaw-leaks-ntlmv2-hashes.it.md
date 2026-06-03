---
title: "Vulnerabilità non corretta nel gestore URI di Windows Search espone hash NTLMv2"
date: "2026-06-03T11:53:18Z"
original_date: "2026-06-03T10:18:52"
lang: "it"
translationKey: "unpatched-windows-search-uri-flaw-leaks-ntlmv2-hashes"
author: "NewsBot (Validated by Federico Sella)"
description: "I ricercatori rivelano una vulnerabilità non corretta nel gestore URI di Windows search: che può esporre hash NTLMv2, simile al difetto CVE-2026-33829 dello Strumento di cattura."
original_url: "https://thehackernews.com/2026/06/unpatched-windows-search-uri.html"
source: "The Hacker News"
severity: "High"
target: "Gestore URI di Windows search:"
cve: null
cvss: null
kev: null
tags: ["news", "cybersecurity"]
news-categories: ["cybersecurity"]
layout: "news"
draft: false
---

I ricercatori rivelano una vulnerabilità non corretta nel gestore URI di Windows search: che può esporre hash NTLMv2, simile al difetto CVE-2026-33829 dello Strumento di cattura.

{{< cyber-report severity="High" source="The Hacker News" target="Gestore URI di Windows search:" >}}

I ricercatori di cybersecurity di Huntress hanno rivelato i dettagli di una vulnerabilità non corretta nel gestore URI di Windows search: che potrebbe consentire agli aggressori di rubare hash NTLMv2. Il problema ricorda CVE-2026-33829, una vulnerabilità di spoofing nel gestore URI ms-screensketch dello Strumento di cattura di Windows che esponeva anch'essa hash NTLM.

{{< ad-banner >}}

Il difetto appena identificato risiede nello schema URI search:, utilizzato per avviare le ricerche di Windows Search. Creando un collegamento o file malevolo che attiva il gestore URI search:, un aggressore può forzare il sistema di destinazione ad autenticarsi verso un server remoto, perdendo così l'hash NTLMv2 dell'utente. Questo hash può poi essere decifrato offline o utilizzato in attacchi di relay.

Alla data di pubblicazione, Microsoft non ha rilasciato alcuna patch ufficiale. Si consiglia alle organizzazioni di monitorare gli aggiornamenti e considerare il blocco del gestore URI search: tramite criteri di gruppo o strumenti di sicurezza degli endpoint fino a quando non sarà disponibile una correzione.

{{< netrunner-insight >}}

Questo è un classico vettore di relay NTLM che gli analisti SOC dovrebbero monitorare nei log di autenticazione. Gli ingegneri DevSecOps dovrebbero rivedere immediatamente qualsiasi uso di gestori URI nei loro ambienti e considerare l'applicazione di mitigazioni come la disabilitazione di NTLMv2 o l'imposizione della firma SMB. Fino a quando Microsoft non correggerà il problema, si presuppone che l'URI search: sia un potenziale punto di ingresso per il furto di credenziali.

{{< /netrunner-insight >}}

---

**[Leggi l'articolo completo su The Hacker News ›](https://thehackernews.com/2026/06/unpatched-windows-search-uri.html)**
