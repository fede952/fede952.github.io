---
title: "HollowFrame Loader e Backdoor Matryoshka Colpiscono uno Studio Legale"
date: "2026-08-01T09:01:20Z"
original_date: "2026-07-31T16:39:31"
lang: "it"
translationKey: "hollowframe-loader-and-matryoshka-backdoor-target-law-firm"
slug: "hollowframe-loader-and-matryoshka-backdoor-target-law-firm"
author: "NewsBot (Validated by Federico Sella)"
description: "Un nuovo loader basato su Go, HollowFrame, e una backdoor basata su Rust, Matryoshka, sono stati utilizzati in un attacco di spear-phishing contro uno studio legale, secondo Blackpoint Cyber."
original_url: "https://thehackernews.com/2026/07/hollowframe-loader-deploys-matryoshka.html"
source: "The Hacker News"
severity: "High"
target: "Studio legale"
cve: null
cvss: null
kev: null
tags: ["news", "cybersecurity"]
news-categories: ["cybersecurity"]
layout: "news"
draft: false
---

Un nuovo loader basato su Go, HollowFrame, e una backdoor basata su Rust, Matryoshka, sono stati utilizzati in un attacco di spear-phishing contro uno studio legale, secondo Blackpoint Cyber.

{{< cyber-report severity="High" source="The Hacker News" target="Studio legale" >}}

Blackpoint Cyber ha scoperto una nuova catena di attacco che prende di mira uno studio legale, a partire da un'email di spear-phishing che induce la vittima a scaricare un archivio crittografato. L'archivio contiene un file di collegamento di Windows (LNK) che, una volta eseguito, avvia un processo di infezione in più fasi.

{{< ad-banner >}}

L'attacco sfrutta due famiglie di malware precedentemente non documentate: HollowFrame, un framework loader basato su Go, e Matryoshka, una backdoor basata su Rust. Il loader è responsabile della consegna della backdoor, che fornisce agli aggressori accesso remoto al sistema compromesso.

Questa campagna evidenzia la continua evoluzione degli strumenti malware, con gli aggressori che adottano linguaggi multipiattaforma come Go e Rust per eludere il rilevamento e complicare l'analisi. L'uso di archivi crittografati e file LNK nello spear-phishing è una tattica comune, ma la combinazione di questi strumenti specifici aggiunge un nuovo livello di sofisticazione.

{{< netrunner-insight >}}

Gli analisti SOC dovrebbero dare priorità al monitoraggio delle esecuzioni di file LNK e dei download di archivi da link email, poiché questi sono indicatori precoci di questa catena di attacco. I team DevSecOps dovrebbero considerare di bloccare o eseguire in sandbox l'esecuzione di file da archivi crittografati e assicurarsi che le soluzioni di endpoint detection and response (EDR) siano configurate per rilevare binari Go e Rust che mostrano comportamento da loader.

{{< /netrunner-insight >}}

---

**[Leggi l'articolo completo su The Hacker News ›](https://thehackernews.com/2026/07/hollowframe-loader-deploys-matryoshka.html)**
