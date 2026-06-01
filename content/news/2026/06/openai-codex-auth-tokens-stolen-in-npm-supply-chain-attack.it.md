---
title: "Token di Autenticazione di OpenAI Codex Rubati in un Attacco alla Supply Chain npm"
date: "2026-06-01T12:34:23Z"
original_date: "2026-06-01T09:31:15"
lang: "it"
translationKey: "openai-codex-auth-tokens-stolen-in-npm-supply-chain-attack"
author: "NewsBot (Validated by Federico Sella)"
description: "Il pacchetto npm malevolo codexui-android prende di mira gli sviluppatori, rubando token di autenticazione di OpenAI Codex con oltre 29.000 download settimanali."
original_url: "https://thehackernews.com/2026/06/openai-codex-authentication-tokens.html"
source: "The Hacker News"
severity: "High"
target: "Sviluppatori di OpenAI Codex"
cve: null
cvss: null
kev: null
tags: ["news", "cybersecurity"]
news-categories: ["cybersecurity"]
layout: "news"
draft: false
---

Il pacchetto npm malevolo codexui-android prende di mira gli sviluppatori, rubando token di autenticazione di OpenAI Codex con oltre 29.000 download settimanali.

{{< cyber-report severity="High" source="The Hacker News" target="Sviluppatori di OpenAI Codex" >}}

I ricercatori di cybersecurity hanno scoperto una campagna malevola alla supply chain che prende di mira gli sviluppatori che utilizzano OpenAI Codex. L'attacco sfrutta un pacchetto npm dall'aspetto legittimo chiamato codexui-android, pubblicizzato come un'interfaccia web remota per OpenAI Codex sia su GitHub che su npm. Il pacchetto ha attirato oltre 29.000 download settimanali, indicando una portata significativa all'interno della comunità degli sviluppatori.

{{< ad-banner >}}

Il pacchetto malevolo è progettato per rubare i token di autenticazione di OpenAI Codex da sviluppatori ignari. Al momento del rapporto, il pacchetto rimane disponibile per il download, rappresentando una minaccia continua. Gli sviluppatori che hanno installato codexui-android sono invitati a ruotare immediatamente i propri token e a verificare i propri sistemi per accessi non autorizzati.

Questo incidente evidenzia il rischio persistente degli attacchi alla supply chain nell'ecosistema open-source. L'uso di nomi di pacchetti dall'aspetto legittimo e di elevati conteggi di download può indurre gli sviluppatori a un falso senso di sicurezza. Le organizzazioni dovrebbero implementare processi rigorosi di verifica dei pacchetti e considerare l'uso di strumenti che rilevano comportamenti anomali dei pacchetti.

{{< netrunner-insight >}}

Per gli analisti SOC e gli ingegneri DevSecOps, questo attacco sottolinea la necessità di monitorare i download e il comportamento dei pacchetti npm. Implementare il rilevamento runtime per l'esfiltrazione inaspettata di token e applicare l'accesso con privilegi minimi per i token API. Verificare regolarmente la propria supply chain software e considerare l'uso di strumenti di verifica dell'integrità dei pacchetti.

{{< /netrunner-insight >}}

---

**[Leggi l'articolo completo su The Hacker News ›](https://thehackernews.com/2026/06/openai-codex-authentication-tokens.html)**
