---
title: "Tre vulnerabilità in OpenClaw consentono una catena d'attacco da WhatsApp all'host"
date: "2026-07-11T08:46:01Z"
original_date: "2026-07-10T14:19:50"
lang: "it"
translationKey: "three-openclaw-flaws-enable-whatsapp-to-host-attack-chain"
slug: "three-openclaw-flaws-enable-whatsapp-to-host-attack-chain"
author: "NewsBot (Validated by Federico Sella)"
description: "Un ricercatore descrive tre vulnerabilità ad alta gravità in OpenClaw che potrebbero consentire il furto di credenziali, l'escalation dei privilegi e l'esecuzione di codice sull'host."
original_url: "https://thehackernews.com/2026/07/researcher-details-whatsapp-to-host.html"
source: "The Hacker News"
severity: "High"
target: "Assistente AI OpenClaw"
cve: null
cvss: 8.8
kev: null
tags: ["news", "cybersecurity"]
news-categories: ["cybersecurity"]
layout: "news"
draft: false
---

Un ricercatore descrive tre vulnerabilità ad alta gravità in OpenClaw che potrebbero consentire il furto di credenziali, l'escalation dei privilegi e l'esecuzione di codice sull'host.

{{< cyber-report severity="High" source="The Hacker News" target="Assistente AI OpenClaw" cvss="8.8" >}}

Sono emersi dettagli su tre falle di sicurezza ora corrette nell'assistente AI personale OpenClaw che, se sfruttate con successo, potrebbero consentire il furto di credenziali, l'escalation dei privilegi e l'esecuzione arbitraria di codice sull'host. Le vulnerabilità sono state divulgate da un ricercatore che ha delineato una catena d'attacco a partire dai messaggi WhatsApp.

{{< ad-banner >}}

Una delle falle, tracciata come GHSA-hjr6-g723-hmfm con un punteggio CVSS di 8.8, è descritta come ad alta gravità. La natura esatta delle altre due vulnerabilità non è stata completamente dettagliata, ma collettivamente rappresentano un rischio significativo per gli utenti che integrano OpenClaw con piattaforme di messaggistica come WhatsApp.

La catena d'attacco sfrutta la capacità dell'assistente AI di elaborare messaggi, consentendo potenzialmente a un attaccante di escalare i privilegi ed eseguire codice arbitrario sul sistema host. Si consiglia agli utenti di applicare le ultime patch per mitigare questi rischi.

{{< netrunner-insight >}}

Questa catena d'attacco evidenzia i rischi dell'integrazione degli assistenti AI con le piattaforme di messaggistica. Gli analisti SOC dovrebbero monitorare esecuzioni di processi anomale provenienti da componenti dell'assistente AI, mentre i team DevSecOps devono garantire che tali integrazioni siano isolate in sandbox e aggiornate tempestivamente.

{{< /netrunner-insight >}}

---

**[Leggi l'articolo completo su The Hacker News ›](https://thehackernews.com/2026/07/researcher-details-whatsapp-to-host.html)**
