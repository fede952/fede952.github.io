---
title: "Nuovo QuimaRAT MaaS basato su Java colpisce Windows, Linux e macOS"
date: "2026-07-06T11:23:53Z"
original_date: "2026-07-06T08:13:33"
lang: "it"
translationKey: "new-java-based-quimarat-maas-targets-windows-linux-macos"
slug: "new-java-based-quimarat-maas-targets-windows-linux-macos"
author: "NewsBot (Validated by Federico Sella)"
description: "QuimaRAT, un RAT Java multipiattaforma venduto come malware-as-a-service, minaccia i sistemi Windows, Linux e macOS. I ricercatori di LevelBlue descrivono il suo modello di abbonamento e le sue capacità."
original_url: "https://thehackernews.com/2026/07/new-java-based-quimarat-maas-built-to.html"
source: "The Hacker News"
severity: "High"
target: "Sistemi Windows, Linux e macOS"
cve: null
cvss: null
kev: null
tags: ["news", "cybersecurity"]
news-categories: ["cybersecurity"]
layout: "news"
draft: false
---

QuimaRAT, un RAT Java multipiattaforma venduto come malware-as-a-service, minaccia i sistemi Windows, Linux e macOS. I ricercatori di LevelBlue descrivono il suo modello di abbonamento e le sue capacità.

{{< cyber-report severity="High" source="The Hacker News" target="Sistemi Windows, Linux e macOS" >}}

I ricercatori di cybersecurity di LevelBlue hanno identificato un nuovo trojan ad accesso remoto (RAT) basato su Java chiamato QuimaRAT, in grado di colpire ambienti Windows, Linux e macOS. Il malware viene commercializzato con un modello malware-as-a-service (MaaS), con livelli di abbonamento che vanno da 150 dollari per un mese a 1.200 dollari per l'accesso a vita, oltre a un livello da 300 dollari.

{{< ad-banner >}}

La natura multipiattaforma di QuimaRAT, resa possibile da Java, gli consente di compromettere diversi sistemi operativi, rendendolo una minaccia versatile per le organizzazioni con ambienti eterogenei. Il modello MaaS abbassa la barriera d'ingresso per gli attori delle minacce meno esperti, aumentando potenzialmente la frequenza degli attacchi.

Sebbene i dettagli tecnici specifici sulle capacità di QuimaRAT siano limitati nel rapporto iniziale, la sua architettura basata su Java suggerisce che potrebbe sfruttare tecniche comuni come la registrazione delle battute, l'acquisizione dello schermo e l'esfiltrazione di file. Le organizzazioni dovrebbero monitorare i processi Java sospetti e implementare l'allowlisting delle applicazioni per mitigare il rischio.

{{< netrunner-insight >}}

Per gli analisti SOC, la natura multipiattaforma di QuimaRAT significa che le regole di rilevamento devono coprire gli endpoint Windows, Linux e macOS. I team DevSecOps dovrebbero rivedere l'uso del runtime Java e considerare di limitare l'esecuzione di applicazioni Java non firmate. Dato il modello MaaS, ci si aspetta che attaccanti con bassa sofisticazione distribuiscano questo RAT, quindi è fondamentale il monitoraggio di base per connessioni di rete e comportamenti di processo insoliti.

{{< /netrunner-insight >}}

---

**[Leggi l'articolo completo su The Hacker News ›](https://thehackernews.com/2026/07/new-java-based-quimarat-maas-built-to.html)**
