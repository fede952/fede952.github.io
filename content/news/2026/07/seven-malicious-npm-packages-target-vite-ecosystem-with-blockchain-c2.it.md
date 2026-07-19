---
title: "Sette pacchetti npm dannosi prendono di mira l'ecosistema Vite con C2 basato su blockchain"
date: "2026-07-19T09:03:59Z"
original_date: "2026-07-17T18:54:51"
lang: "it"
translationKey: "seven-malicious-npm-packages-target-vite-ecosystem-with-blockchain-c2"
slug: "seven-malicious-npm-packages-target-vite-ecosystem-with-blockchain-c2"
author: "NewsBot (Validated by Federico Sella)"
description: "Checkmarx scopre la campagna ViteVenom che utilizza infrastruttura C2 basata su blockchain per distribuire un RAT tramite sette pacchetti npm dannosi che prendono di mira il frontend tooling Vite."
original_url: "https://thehackernews.com/2026/07/seven-malicious-vite-npm-packages-use.html"
source: "The Hacker News"
severity: "High"
target: "Ecosistema del frontend tooling Vite"
cve: null
cvss: null
kev: null
tags: ["news", "cybersecurity"]
news-categories: ["cybersecurity"]
layout: "news"
draft: false
---

Checkmarx scopre la campagna ViteVenom che utilizza infrastruttura C2 basata su blockchain per distribuire un RAT tramite sette pacchetti npm dannosi che prendono di mira il frontend tooling Vite.

{{< cyber-report severity="High" source="The Hacker News" target="Ecosistema del frontend tooling Vite" >}}

I ricercatori di sicurezza informatica di Checkmarx hanno identificato un cluster di sette pacchetti npm dannosi che prendono di mira l'ecosistema del frontend tooling Vite come parte di un attacco alla supply chain del software. La campagna, nome in codice ViteVenom, rappresenta un'espansione della precedentemente osservata operazione ChainVeil, che utilizzava un'infrastruttura di comando e controllo (C2) basata su blockchain a quattro livelli senza precedenti, estesa sulla rete Tron.

{{< ad-banner >}}

I pacchetti dannosi sono progettati per distribuire un trojan ad accesso remoto (RAT) ai sistemi compromessi, consentendo agli aggressori di esfiltrare dati e mantenere un accesso persistente. L'uso della blockchain per le comunicazioni C2 rende più difficile il rilevamento e lo smantellamento, poiché l'infrastruttura è decentralizzata e resistente alle tecniche tradizionali di sinkholing.

Le organizzazioni che utilizzano Vite nelle loro pipeline di sviluppo dovrebbero immediatamente verificare le loro dipendenze per i pacchetti dannosi identificati e implementare controlli rigorosi sull'integrità dei pacchetti. Questo incidente evidenzia la crescente sofisticazione degli attacchi alla supply chain del software, in cui gli aggressori sfruttano strumenti di sviluppo legittimi e reti decentralizzate per eludere il rilevamento.

{{< netrunner-insight >}}

Per gli analisti SOC, monitorare le connessioni in uscita verso nodi blockchain e query DNS insolite può aiutare a rilevare questa tecnica C2. I team DevSecOps dovrebbero imporre la firma dei pacchetti e utilizzare strumenti di scansione delle dipendenze per bloccare i pacchetti dannosi noti prima che entrino nella pipeline di build.

{{< /netrunner-insight >}}

---

**[Leggi l'articolo completo su The Hacker News ›](https://thehackernews.com/2026/07/seven-malicious-vite-npm-packages-use.html)**
