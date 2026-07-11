---
title: "Nuovo RAT MODBEACON utilizza lo streaming gRPC per traffico C2 crittografato"
date: "2026-07-11T08:43:59Z"
original_date: "2026-07-10T13:15:23"
lang: "it"
translationKey: "new-modbeacon-rat-uses-grpc-streaming-for-encrypted-c2-traffic"
slug: "new-modbeacon-rat-uses-grpc-streaming-for-encrypted-c2-traffic"
author: "NewsBot (Validated by Federico Sella)"
description: "Il gruppo Silver Fox legato alla Cina distribuisce il RAT MODBEACON basato su Rust tramite avvelenamento SEO, utilizzando lo streaming gRPC per comunicazioni C2 crittografate."
original_url: "https://thehackernews.com/2026/07/new-modbeacon-rat-uses-grpc-streaming.html"
source: "The Hacker News"
severity: "High"
target: "Utenti Windows tramite installer contraffatti"
cve: null
cvss: null
kev: null
tags: ["news", "cybersecurity"]
news-categories: ["cybersecurity"]
layout: "news"
draft: false
---

Il gruppo Silver Fox legato alla Cina distribuisce il RAT MODBEACON basato su Rust tramite avvelenamento SEO, utilizzando lo streaming gRPC per comunicazioni C2 crittografate.

{{< cyber-report severity="High" source="The Hacker News" target="Utenti Windows tramite installer contraffatti" >}}

Il gruppo di cybercriminali Silver Fox, legato alla Cina, è stato attribuito a un nuovo trojan ad accesso remoto (RAT) basato su Rust chiamato MODBEACON. Il malware utilizza lo streaming gRPC per il traffico crittografato di comando e controllo (C2), rendendo il rilevamento più difficile.

{{< ad-banner >}}

Secondo l'azienda cinese di cybersecurity QiAnXin, Silver Fox propaga MODBEACON tramite installer contraffatti utilizzando tecniche di avvelenamento SEO. Sebbene il gruppo possa apparire come un'operazione a bassa sofisticazione ma ad alta attività, le loro reali capacità organizzative sono più avanzate.

L'uso dello streaming gRPC per la comunicazione C2 rappresenta una tecnica innovativa per il malware, poiché sfrutta HTTP/2 e buffer di protocollo per mimetizzarsi con il traffico legittimo. I team di sicurezza dovrebbero monitorare il traffico gRPC insolito e indagare sui siti di download avvelenati tramite SEO.

{{< netrunner-insight >}}

Gli analisti SOC dovrebbero aggiungere l'analisi del traffico gRPC alle loro pipeline di rilevamento, poiché l'uso di RPC in streaming da parte di MODBEACON può eludere le firme di rete tradizionali. I team DevSecOps devono verificare l'integrità dei download di software e considerare il blocco dei domini noti per avvelenamento SEO. Questo RAT sottolinea la necessità di una caccia proattiva alle minacce contro il malware basato su Rust.

{{< /netrunner-insight >}}

---

**[Leggi l'articolo completo su The Hacker News ›](https://thehackernews.com/2026/07/new-modbeacon-rat-uses-grpc-streaming.html)**
