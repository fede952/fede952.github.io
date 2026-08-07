---
title: "TeamPCP collegato ad attacchi Redis dal 2020, poi campagna di supply chain"
date: "2026-08-07T08:10:37Z"
original_date: "2026-08-07T06:50:05"
lang: "it"
translationKey: "teampcp-linked-to-redis-attacks-since-2020-later-supply-chain-campaign"
slug: "teampcp-linked-to-redis-attacks-since-2020-later-supply-chain-campaign"
author: "NewsBot (Validated by Federico Sella)"
description: "Una nuova analisi collega TeamPCP ad attacchi Redis risalenti al 2020, rivelando anni di compromissione di infrastrutture prima del focus sulla supply chain."
original_url: "https://thehackernews.com/2026/08/teampcp-linked-to-redis-attacks-dating.html"
source: "The Hacker News"
severity: "Medium"
target: "Infrastruttura esposta a Internet"
cve: null
cvss: null
kev: null
tags: ["news", "cybersecurity"]
news-categories: ["cybersecurity"]
layout: "news"
draft: false
---

Una nuova analisi collega TeamPCP ad attacchi Redis risalenti al 2020, rivelando anni di compromissione di infrastrutture prima del focus sulla supply chain.

{{< cyber-report severity="Medium" source="The Hacker News" target="Infrastruttura esposta a Internet" >}}

Una recente analisi ha scoperto che l'attore minaccioso noto come TeamPCP è attivo nella scena del cybercrimine da almeno il 2020, indicando una lunga storia di compromissione di infrastrutture esposte a Internet. Le attività del gruppo sono ora state collegate a una successiva campagna di supply chain software, suggerendo un'evoluzione strategica nelle loro operazioni.

{{< ad-banner >}}

La connessione tra i precedenti attacchi Redis e la campagna di supply chain è supportata da domini sovrapposti, percorsi di distribuzione del malware, tecniche di staging e infrastruttura backend. Queste somiglianze forniscono forti prove che lo stesso attore sia responsabile di entrambe le serie di attività, evidenziando l'importanza dell'intelligence storica sulle minacce nell'attribuire e comprendere gli attacchi moderni.

Per i difensori, questa timeline sottolinea la necessità di monitorare gli indicatori di compromissione che possono estendersi per anni e di considerare la possibilità che gli attori minacciosi passino da attacchi opportunistici a operazioni di supply chain più mirate. I risultati enfatizzano anche il valore della condivisione dell'intelligence sulle minacce tra organizzazioni per identificare tali modelli a lungo termine.

{{< netrunner-insight >}}

Per gli analisti SOC, questo report rafforza l'importanza di correlare gli indicatori storici con le minacce attuali: l'uso da parte di TeamPCP di infrastrutture sovrapposte significa che i vecchi IoC potrebbero essere ancora rilevanti. I team DevSecOps dovrebbero trattare i servizi esposti a Internet come Redis come obiettivi ad alto valore e garantire una robusta gestione delle patch e un monitoraggio, poiché gli attaccanti potrebbero rimanere in agguato per anni prima di colpire. I difensori della supply chain dovrebbero anche verificare i componenti di terze parti per legami con infrastrutture dannose note, poiché questo gruppo dimostra una chiara progressione da attacchi diretti a compromissioni più insidiose della supply chain.

{{< /netrunner-insight >}}

---

**[Leggi l'articolo completo su The Hacker News ›](https://thehackernews.com/2026/08/teampcp-linked-to-redis-attacks-dating.html)**
