---
title: "Botnet xlabs_v1 derivato da Mirai dirotta dispositivi IoT tramite ADB per DDoS"
date: "2026-05-07T09:27:29Z"
original_date: "2026-05-06T20:21:00"
lang: "it"
translationKey: "mirai-derived-xlabs-v1-botnet-hijacks-iot-devices-via-adb-for-ddos"
author: "NewsBot (Validated by Federico Sella)"
description: "I ricercatori scoprono xlabs_v1, una nuova botnet basata su Mirai che sfrutta le porte Android Debug Bridge esposte per reclutare dispositivi IoT in una rete DDoS."
original_url: "https://thehackernews.com/2026/05/mirai-based-xlabsv1-botnet-exploits-adb.html"
source: "The Hacker News"
severity: "High"
target: "Dispositivi IoT con ADB esposto"
cve: null
cvss: null
kev: null
tags: ["news", "cybersecurity"]
news-categories: ["cybersecurity"]
layout: "news"
draft: false
---

I ricercatori scoprono xlabs_v1, una nuova botnet basata su Mirai che sfrutta le porte Android Debug Bridge esposte per reclutare dispositivi IoT in una rete DDoS.

{{< cyber-report severity="High" source="The Hacker News" target="Dispositivi IoT con ADB esposto" >}}

I ricercatori di cybersecurity hanno identificato una nuova botnet derivata da Mirai, auto-identificata come xlabs_v1, che prende di mira dispositivi esposti a Internet che eseguono Android Debug Bridge (ADB). La botnet mira ad arruolare i dispositivi compromessi in una rete in grado di lanciare attacchi di denial-of-service distribuito (DDoS).

{{< ad-banner >}}

La scoperta è stata fatta da Hunt.io dopo aver identificato una directory esposta su un server ospitato nei Paesi Bassi. Il malware sfrutta ADB, uno strumento a riga di comando utilizzato per il debug di dispositivi Android, che spesso viene lasciato esposto sui dispositivi IoT, consentendo a malintenzionati remoti di ottenere accesso non autorizzato.

Questa campagna evidenzia la minaccia continua delle varianti di Mirai che prendono di mira dispositivi IoT poco sicuri. Si consiglia alle organizzazioni di disabilitare ADB sui dispositivi di produzione e limitare l'accesso di rete per prevenire tali dirottamenti.

{{< netrunner-insight >}}

Per gli analisti SOC, monitorare connessioni ADB inaspettate da IP esterni. I team DevSecOps dovrebbero assicurarsi che ADB sia disabilitato nelle build di produzione e che i dispositivi IoT siano segmentati dalle reti critiche per mitigare la portata di questa botnet.

{{< /netrunner-insight >}}

---

**[Leggi l'articolo completo su The Hacker News ›](https://thehackernews.com/2026/05/mirai-based-xlabsv1-botnet-exploits-adb.html)**
