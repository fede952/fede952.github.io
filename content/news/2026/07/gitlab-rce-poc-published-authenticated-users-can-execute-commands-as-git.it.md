---
title: "Pubblicato PoC per RCE in GitLab: utenti autenticati possono eseguire comandi come git"
date: "2026-07-27T10:37:15Z"
original_date: "2026-07-25T10:14:26"
lang: "it"
translationKey: "gitlab-rce-poc-published-authenticated-users-can-execute-commands-as-git"
slug: "gitlab-rce-poc-published-authenticated-users-can-execute-commands-as-git"
author: "NewsBot (Validated by Federico Sella)"
description: "È stato rilasciato un proof-of-concept per una vulnerabilità di esecuzione remota di codice in GitLab, che colpisce i server self-managed 18.11.3 non aggiornati. Gli utenti autenticati possono eseguire comandi come l'utente git."
original_url: "https://thehackernews.com/2026/07/researcher-publishes-gitlab-rce-poc.html"
source: "The Hacker News"
severity: "High"
target: "GitLab self-managed 18.11.3"
cve: null
cvss: null
kev: null
tags: ["news", "cybersecurity"]
news-categories: ["cybersecurity"]
layout: "news"
draft: false
---

È stato rilasciato un proof-of-concept per una vulnerabilità di esecuzione remota di codice in GitLab, che colpisce i server self-managed 18.11.3 non aggiornati. Gli utenti autenticati possono eseguire comandi come l'utente git.

{{< cyber-report severity="High" source="The Hacker News" target="GitLab self-managed 18.11.3" >}}

Il 24 luglio 2026, i ricercatori di sicurezza di depthfirst hanno pubblicato un proof-of-concept funzionante per una vulnerabilità di esecuzione remota di codice in GitLab. Il difetto, corretto da GitLab il 10 giugno 2026, consente a qualsiasi utente autenticato con accesso in push a un progetto di eseguire comandi arbitrari come l'utente git sui server GitLab self-managed 18.11.3 che non hanno applicato l'aggiornamento.

{{< ad-banner >}}

L'exploit sfrutta un notebook Jupyter appositamente creato e committato in un progetto. Quando l'attaccante apre il diff del commit, il notebook malevolo innesca una perdita di heap, consentendo l'esecuzione di comandi. Questa tecnica bypassa i tipici controlli di autenticazione e non richiede privilegi speciali oltre all'accesso standard al progetto.

Le organizzazioni che eseguono istanze GitLab self-managed dovrebbero verificare immediatamente di aver applicato la patch del 10 giugno. La disponibilità pubblica del codice exploit aumenta il rischio di sfruttamento attivo, in particolare per le istanze esposte a Internet. I blue team dovrebbero monitorare commit di notebook Jupyter insoliti e attività inaspettate dell'utente git.

{{< netrunner-insight >}}

Questo exploit sottolinea il pericolo di ritardare l'applicazione delle patch nelle piattaforme CI/CD self-managed. Gli analisti SOC dovrebbero dare priorità al rilevamento di processi anomali dell'utente git e caricamenti imprevisti di notebook Jupyter. I team DevSecOps devono imporre una finestra di patch rigorosa per GitLab e considerare la segmentazione di rete per limitare l'esposizione delle istanze self-managed.

{{< /netrunner-insight >}}

---

**[Leggi l'articolo completo su The Hacker News ›](https://thehackernews.com/2026/07/researcher-publishes-gitlab-rce-poc.html)**
