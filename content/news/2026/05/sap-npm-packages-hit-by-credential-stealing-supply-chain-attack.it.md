---
title: "Pacchetti npm SAP Colpiti da Attacco alla Catena di Fornitura che Ruba Credenziali"
date: "2026-05-03T08:51:39Z"
original_date: "2026-04-29T16:26:00"
lang: "it"
translationKey: "sap-npm-packages-hit-by-credential-stealing-supply-chain-attack"
author: "NewsBot (Validated by Federico Sella)"
description: "Una campagna denominata 'Mini Shai-Hulud' prende di mira pacchetti npm correlati a SAP con malware che ruba credenziali, colpendo diversi pacchetti. Ricercatori di varie aziende avvertono dei rischi per la catena di fornitura."
original_url: "https://thehackernews.com/2026/04/sap-npm-packages-compromised-by-mini.html"
source: "The Hacker News"
severity: "High"
target: "Pacchetti npm correlati a SAP"
cve: null
cvss: null
kev: null
tags: ["news", "cybersecurity"]
news-categories: ["cybersecurity"]
layout: "news"
draft: false
---

Una campagna denominata 'Mini Shai-Hulud' prende di mira pacchetti npm correlati a SAP con malware che ruba credenziali, colpendo diversi pacchetti. Ricercatori di varie aziende avvertono dei rischi per la catena di fornitura.

{{< cyber-report severity="High" source="The Hacker News" target="Pacchetti npm correlati a SAP" >}}

I ricercatori di cybersecurity hanno scoperto una campagna di attacco alla catena di fornitura che prende di mira i pacchetti npm correlati a SAP. Denominata 'Mini Shai-Hulud', la campagna distribuisce malware che ruba credenziali attraverso pacchetti compromessi, secondo quanto riportato da Aikido Security, Onapsis, OX Security, SafeDep, Socket, StepSecurity e Wiz.

{{< ad-banner >}}

L'attacco colpisce diversi pacchetti npm associati a SAP, sebbene i nomi e le versioni specifici dei pacchetti non siano stati divulgati. Il malware è progettato per rubare credenziali, potenzialmente dando agli aggressori accesso ad ambienti SAP sensibili e sistemi a valle.

Questo incidente evidenzia la crescente minaccia alle catene di fornitura software, in particolare per piattaforme critiche aziendali come SAP. Le organizzazioni che utilizzano pacchetti interessati sono invitate a verificare le proprie dipendenze e a ruotare eventuali credenziali potenzialmente compromesse.

{{< netrunner-insight >}}

Per gli analisti SOC e i team DevSecOps, questo attacco sottolinea la necessità di una scansione rigorosa delle dipendenze e di controlli di integrità sui pacchetti npm. Monitorare connessioni in uscita anomale dai sistemi correlati a SAP e considerare l'implementazione della protezione runtime delle applicazioni (RASP) per rilevare il furto di credenziali. Ruotare immediatamente tutte le credenziali che potrebbero essere state esposte attraverso pacchetti compromessi.

{{< /netrunner-insight >}}

---

**[Leggi l'articolo completo su The Hacker News ›](https://thehackernews.com/2026/04/sap-npm-packages-compromised-by-mini.html)**
