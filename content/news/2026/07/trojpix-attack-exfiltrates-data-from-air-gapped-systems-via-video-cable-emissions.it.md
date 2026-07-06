---
title: "Attacco TrojPix esfiltra dati da sistemi air-gapped tramite emissioni di cavi video"
date: "2026-07-06T11:24:53Z"
original_date: "2026-07-06T08:50:54"
lang: "it"
translationKey: "trojpix-attack-exfiltrates-data-from-air-gapped-systems-via-video-cable-emissions"
slug: "trojpix-attack-exfiltrates-data-from-air-gapped-systems-via-video-cable-emissions"
author: "NewsBot (Validated by Federico Sella)"
description: "I ricercatori dimostrano TrojPix, una tecnica che perde dati da computer air-gapped modulando i pixel sullo schermo per emettere deboli segnali radio dai cavi video, richiedendo un precedente accesso malware."
original_url: "https://thehackernews.com/2026/07/new-trojpix-attack-leaks-data-from-air.html"
source: "The Hacker News"
severity: "Medium"
target: "Sistemi air-gapped"
cve: null
cvss: null
kev: null
tags: ["news", "cybersecurity"]
news-categories: ["cybersecurity"]
layout: "news"
draft: false
---

I ricercatori dimostrano TrojPix, una tecnica che perde dati da computer air-gapped modulando i pixel sullo schermo per emettere deboli segnali radio dai cavi video, richiedendo un precedente accesso malware.

{{< cyber-report severity="Medium" source="The Hacker News" target="Sistemi air-gapped" >}}

Ricercatori della Shandong University hanno svelato TrojPix, un nuovo attacco che esfiltra dati da computer air-gapped sfruttando le emissioni elettromagnetiche dei cavi video. La tecnica altera sottilmente i pixel sullo schermo in modo impercettibile all'occhio umano, facendo sì che il cavo video irradi un debole segnale radio che può essere catturato e decodificato da un ricevitore vicino.

{{< ad-banner >}}

TrojPix richiede l'installazione preventiva di malware sul sistema target per manipolare i valori dei pixel. Questo approccio raggiunge velocità di trasferimento dati significativamente più elevate rispetto ai precedenti canali nascosti air-gap, rendendolo una minaccia concreta per ambienti altamente sicuri. L'attacco evidenzia la sfida continua di proteggere i dati anche in reti fisicamente isolate.

Sebbene la tecnica sia sofisticata, la sua dipendenza da malware preesistente ne limita l'applicabilità. Le organizzazioni dovrebbero concentrarsi sulla prevenzione del compromesso iniziale attraverso una solida sicurezza degli endpoint e il monitoraggio di emissioni elettromagnetiche anomale in aree sensibili.

{{< netrunner-insight >}}

Per gli analisti SOC, TrojPix sottolinea che i sistemi air-gapped non sono immuni all'esfiltrazione di dati. Monitorare segnali elettromagnetici anomali vicino a workstation sensibili e applicare una rigorosa sicurezza fisica. I team DevSecOps dovrebbero considerare la schermatura dei cavi video e l'implementazione di rilevamento di anomalie a livello di pixel dove possibile.

{{< /netrunner-insight >}}

---

**[Leggi l'articolo completo su The Hacker News ›](https://thehackernews.com/2026/07/new-trojpix-attack-leaks-data-from-air.html)**
