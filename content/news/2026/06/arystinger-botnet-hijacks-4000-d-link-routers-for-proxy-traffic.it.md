---
title: "Botnet AryStinger dirotta oltre 4.000 router D-Link per traffico proxy"
date: "2026-06-22T12:48:45Z"
original_date: "2026-06-21T14:14:22"
lang: "it"
translationKey: "arystinger-botnet-hijacks-4000-d-link-routers-for-proxy-traffic"
author: "NewsBot (Validated by Federico Sella)"
description: "Una nuova botnet chiamata AryStinger ha compromesso oltre 4.000 router D-Link obsoleti, trasformandoli in proxy per traffico malevolo. Non sono disponibili dati CVE o CVSS."
original_url: "https://www.bleepingcomputer.com/news/security/arystinger-botnet-infected-thousands-of-d-link-routers-worldwide/"
source: "BleepingComputer"
severity: "Medium"
target: "Router D-Link obsoleti"
cve: null
cvss: null
kev: null
tags: ["news", "cybersecurity"]
news-categories: ["cybersecurity"]
layout: "news"
draft: false
---

Una nuova botnet chiamata AryStinger ha compromesso oltre 4.000 router D-Link obsoleti, trasformandoli in proxy per traffico malevolo. Non sono disponibili dati CVE o CVSS.

{{< cyber-report severity="Medium" source="BleepingComputer" target="Router D-Link obsoleti" >}}

Una botnet malware precedentemente sconosciuta chiamata AryStinger ha compromesso oltre 4.000 router D-Link obsoleti in tutto il mondo, secondo un rapporto di BleepingComputer. La botnet trasforma questi dispositivi in proxy per traffico malevolo, consentendo agli aggressori di anonimizzare le proprie attività e potenzialmente lanciare ulteriori attacchi.

{{< ad-banner >}}

Si ritiene che i router compromessi eseguano firmware obsoleto con vulnerabilità note, sebbene nel rapporto non siano stati divulgati identificatori CVE specifici. L'infrastruttura della botnet e i metodi di propagazione sono ancora in fase di analisi, ma la scala dell'infezione evidenzia i rischi posti dai dispositivi IoT non aggiornati.

Si consiglia alle organizzazioni di inventariare i propri dispositivi di rete, assicurarsi che il firmware sia aggiornato e monitorare modelli di traffico insoliti che potrebbero indicare l'uso di proxy. La mancanza di indicatori tecnici dettagliati nel rapporto iniziale suggerisce che siano necessarie ulteriori indagini per sviluppare firme di rilevamento.

{{< netrunner-insight >}}

Per gli analisti SOC, questo è un promemoria per monitorare connessioni in uscita inaspettate dai dispositivi di rete, specialmente router più vecchi. I team DevSecOps dovrebbero applicare politiche di aggiornamento del firmware e considerare la segmentazione dei dispositivi IoT dalle reti critiche. Senza IoC specifici, l'analisi del traffico di base e l'impronta digitale dei dispositivi sono fondamentali per individuare tale attività botnet.

{{< /netrunner-insight >}}

---

**[Leggi l'articolo completo su BleepingComputer ›](https://www.bleepingcomputer.com/news/security/arystinger-botnet-infected-thousands-of-d-link-routers-worldwide/)**
