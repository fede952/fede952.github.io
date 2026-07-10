---
title: "Backdoor GigaWiper combina cancellazione disco, falso ransomware e spyware"
date: "2026-07-10T10:21:21Z"
original_date: "2026-07-09T18:08:07"
lang: "it"
translationKey: "gigawiper-backdoor-combines-disk-wiping-fake-ransomware-and-spyware"
slug: "gigawiper-backdoor-combines-disk-wiping-fake-ransomware-and-spyware"
author: "NewsBot (Validated by Federico Sella)"
description: "Microsoft scopre GigaWiper, una backdoor modulare per Windows che raggruppa tre strumenti distruttivi: cancellatore di disco, falso ransomware e spyware, rappresentando una grave minaccia per gli endpoint."
original_url: "https://thehackernews.com/2026/07/new-gigawiper-windows-backdoor-bundles.html"
source: "The Hacker News"
severity: "High"
target: "Endpoint Windows"
cve: null
cvss: null
kev: null
tags: ["news", "cybersecurity"]
news-categories: ["cybersecurity"]
layout: "news"
draft: false
---

Microsoft scopre GigaWiper, una backdoor modulare per Windows che raggruppa tre strumenti distruttivi: cancellatore di disco, falso ransomware e spyware, rappresentando una grave minaccia per gli endpoint.

{{< cyber-report severity="High" source="The Hacker News" target="Endpoint Windows" >}}

Microsoft ha identificato una nuova backdoor distruttiva per Windows chiamata GigaWiper, che integra tre programmi dannosi più vecchi in un unico framework modulare. La backdoor offre agli operatori un menu di comandi tra cui scegliere, ciascuno progettato per infliggere un diverso tipo di danno: cancellazione completa del disco, sovrascrittura dell'unità di sistema di Windows o esecuzione di un falso ransomware che crittografa i file con una chiave mai salvata.

{{< ad-banner >}}

Il design modulare di GigaWiper consente agli aggressori di personalizzare le loro azioni distruttive in base all'ambiente target. L'inclusione di capacità di cancellazione del disco e falso ransomware suggerisce che l'obiettivo principale sia causare il massimo di interruzione e perdita di dati, piuttosto che un guadagno finanziario. Questa combinazione di tecniche rende GigaWiper uno strumento versatile e pericoloso per operazioni cyber distruttive.

Sebbene il vettore di distribuzione specifico rimanga non divulgato, la capacità della backdoor di cancellare interi dischi e simulare attacchi ransomware indica un alto livello di sofisticazione. Le organizzazioni dovrebbero dare priorità a soluzioni di rilevamento e risposta degli endpoint (EDR) e garantire strategie di backup robuste per mitigare l'impatto di tali minacce.

{{< netrunner-insight >}}

Per gli analisti SOC, GigaWiper sottolinea la necessità di regole di rilevamento comportamentale che segnalino operazioni massive sui file e scritture a livello di disco. I team DevSecOps dovrebbero validare l'integrità dei backup e testare regolarmente le procedure di ripristino, poiché il falso ransomware può bypassare gli approcci di decrittazione tradizionali. Tratta qualsiasi incidente ransomware non verificato come un potenziale attacco wiper fino a prova contraria.

{{< /netrunner-insight >}}

---

**[Leggi l'articolo completo su The Hacker News ›](https://thehackernews.com/2026/07/new-gigawiper-windows-backdoor-bundles.html)**
