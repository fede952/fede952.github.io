---
title: "Pacchetti RubyGems con Typosquatting Rubano Credenziali del Browser e Portafogli Crypto"
date: "2026-08-19T07:36:21Z"
original_date: "2026-08-18T11:20:00"
lang: "it"
translationKey: "typosquatted-rubygems-packages-steal-browser-credentials-and-crypto-wallets"
slug: "typosquatted-rubygems-packages-steal-browser-credentials-and-crypto-wallets"
author: "NewsBot (Validated by Federico Sella)"
description: "I ricercatori segnalano 16 pacchetti RubyGems con typosquatting che distribuiscono un info stealer basato su Windows, prendendo di mira le credenziali del browser e i portafogli crypto."
original_url: "https://thehackernews.com/2026/08/16-typosquatted-rubygems-packages-steal.html"
source: "The Hacker News"
severity: "High"
target: "Utenti RubyGems su Windows"
cve: null
cvss: null
kev: null
tags: ["news", "cybersecurity"]
news-categories: ["cybersecurity"]
layout: "news"
draft: false
---

I ricercatori segnalano 16 pacchetti RubyGems con typosquatting che distribuiscono un info stealer basato su Windows, prendendo di mira le credenziali del browser e i portafogli crypto.

{{< cyber-report severity="High" source="The Hacker News" target="Utenti RubyGems su Windows" >}}

I ricercatori di cybersecurity hanno scoperto una nuova campagna di typosquatting che prende di mira gli utenti RubyGems, distribuendo un info stealer basato su Windows. La campagna, monitorata come StubMaker, è stata scoperta il 15 agosto 2026 da OpenSourceMalware e coinvolge 16 pacchetti dannosi progettati per rubare credenziali del browser e portafogli di criptovaluta.

{{< ad-banner >}}

I pacchetti dannosi, che includono nomi come 'ubnuler', 'ubnlder', 'ri18nr', 'reaker', 'rakier', 'orakw' e 'joxn', sono probabilmente typosquat di gemme popolari, ingannando gli sviluppatori affinché li installino. Una volta installati, lo stealer raccoglie dati sensibili da browser ed estensioni di portafogli crypto, rappresentando un rischio significativo per la supply chain.

Questa campagna evidenzia la minaccia continua del typosquatting negli ecosistemi open-source. Si consiglia agli sviluppatori di verificare attentamente i nomi dei pacchetti, utilizzare fonti affidabili e monitorare le dipendenze sospette nei loro progetti.

{{< netrunner-insight >}}

Per gli analisti SOC, questa campagna sottolinea la necessità di monitorare installazioni RubyGems inaspettate e chiamate di rete verso domini sospetti. Gli ingegneri DevSecOps dovrebbero applicare il blocco rigoroso delle dipendenze e utilizzare strumenti che scansionano i pacchetti typosquattati. Inoltre, considerare di bloccare i nomi di pacchetti dannosi noti e istruire gli sviluppatori sui rischi del typosquatting.

{{< /netrunner-insight >}}

---

**[Leggi l'articolo completo su The Hacker News ›](https://thehackernews.com/2026/08/16-typosquatted-rubygems-packages-steal.html)**
