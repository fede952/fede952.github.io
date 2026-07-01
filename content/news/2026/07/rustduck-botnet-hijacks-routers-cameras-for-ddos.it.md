---
title: "Botnet RustDuck dirotta router e telecamere per attacchi DDoS"
date: "2026-07-01T10:41:08Z"
original_date: "2026-06-30T17:45:25"
lang: "it"
translationKey: "rustduck-botnet-hijacks-routers-cameras-for-ddos"
author: "NewsBot (Validated by Federico Sella)"
description: "Una nuova famiglia di malware a due stadi chiamata RustDuck sta dirottando router domestici, telecamere IP, Android box e server poco protetti per costruire una rete DDoS, monitorata da febbraio 2026."
original_url: "https://thehackernews.com/2026/06/rustduck-botnet-rebuilds-in-rust-to.html"
source: "The Hacker News"
severity: "High"
target: "Router, telecamere IP, Android box, server"
cve: null
cvss: null
kev: null
tags: ["news", "cybersecurity"]
news-categories: ["cybersecurity"]
layout: "news"
draft: false
---

Una nuova famiglia di malware a due stadi chiamata RustDuck sta dirottando router domestici, telecamere IP, Android box e server poco protetti per costruire una rete DDoS, monitorata da febbraio 2026.

{{< cyber-report severity="High" source="The Hacker News" target="Router, telecamere IP, Android box, server" >}}

I ricercatori di QiAnXin's XLab stanno monitorando una nuova famiglia di malware a due stadi chiamata RustDuck da febbraio 2026. La botnet dirotta router domestici, telecamere IP, Android box e server poco protetti, assemblandoli in una rete progettata per mettere offline siti web e servizi online tramite attacchi DDoS.

{{< ad-banner >}}

Il malware è notevole per essere stato riscritto in Rust, un linguaggio memory-safe che complica l'analisi e il reverse engineering. Sebbene le dimensioni attuali della botnet non siano enormi, la sua rapida evoluzione e adattabilità rappresentano una minaccia crescente per l'infrastruttura internet.

RustDuck rappresenta un cambiamento nello sviluppo delle botnet, sfruttando le caratteristiche di performance e sicurezza di Rust per creare malware più resilienti e difficili da rilevare. L'obiettivo finale è costruire una robusta rete DDoS in grado di abbattere bersagli importanti.

{{< netrunner-insight >}}

Per gli analisti SOC: monitorare il traffico in uscita anomalo da dispositivi IoT e router, poiché l'infezione a due stadi di RustDuck potrebbe eludere le firme tradizionali. I team DevSecOps dovrebbero imporre una rigorosa segmentazione di rete e disabilitare servizi non necessari sui dispositivi esposti per ridurre la superficie d'attacco.

{{< /netrunner-insight >}}

---

**[Leggi l'articolo completo su The Hacker News ›](https://thehackernews.com/2026/06/rustduck-botnet-rebuilds-in-rust-to.html)**
