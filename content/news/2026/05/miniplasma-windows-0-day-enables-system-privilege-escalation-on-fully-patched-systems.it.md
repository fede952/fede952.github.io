---
title: "MiniPlasma Windows 0-Day Consente l'Escalation dei Privilegi a SYSTEM su Sistemi Completamente Aggiornati"
date: "2026-05-18T11:01:35Z"
original_date: "2026-05-18T08:57:34"
lang: "it"
translationKey: "miniplasma-windows-0-day-enables-system-privilege-escalation-on-fully-patched-systems"
author: "NewsBot (Validated by Federico Sella)"
description: "Il ricercatore di sicurezza Chaotic Eclipse rilascia un PoC per MiniPlasma, una vulnerabilità zero-day nel driver Mini Filter di Windows Cloud Files (cldflt.sys) che concede privilegi SYSTEM su sistemi completamente aggiornati."
original_url: "https://thehackernews.com/2026/05/miniplasma-windows-0-day-enables-system.html"
source: "The Hacker News"
severity: "High"
target: "Windows Cloud Files Mini Filter Driver (cldflt.sys)"
cve: null
cvss: null
kev: null
tags: ["news", "cybersecurity"]
news-categories: ["cybersecurity"]
layout: "news"
draft: false
---

Il ricercatore di sicurezza Chaotic Eclipse rilascia un PoC per MiniPlasma, una vulnerabilità zero-day nel driver Mini Filter di Windows Cloud Files (cldflt.sys) che concede privilegi SYSTEM su sistemi completamente aggiornati.

{{< cyber-report severity="High" source="The Hacker News" target="Windows Cloud Files Mini Filter Driver (cldflt.sys)" >}}

Chaotic Eclipse, il ricercatore di sicurezza dietro le recenti vulnerabilità Windows divulgate YellowKey e GreenPlasma, ha rilasciato un proof-of-concept (PoC) per una vulnerabilità zero-day di escalation dei privilegi Windows che consente agli aggressori di ottenere privilegi SYSTEM su sistemi Windows completamente aggiornati. Soprannominata MiniPlasma, la vulnerabilità impatta "cldflt.sys", che si riferisce al driver Mini Filter di Windows Cloud Files.

{{< ad-banner >}}

La falla consente a un utente con accesso limitato di escalare i privilegi a SYSTEM, potenzialmente permettendo il compromesso totale del sistema. Essendo una zero-day, non è attualmente disponibile alcuna patch ufficiale, lasciando i sistemi completamente aggiornati vulnerabili allo sfruttamento se il PoC viene armato.

Le organizzazioni dovrebbero monitorare comportamenti anomali dal driver cldflt.sys e considerare misure di hardening aggiuntive, come limitare l'accesso alla funzionalità Cloud Files o applicare mitigazioni temporanee fino al rilascio di una patch.

{{< netrunner-insight >}}

Gli analisti SOC dovrebbero dare priorità al monitoraggio dei tentativi di sfruttamento che mirano a cldflt.sys, poiché il PoC abbassa la barriera per gli aggressori. I team DevSecOps dovrebbero rivedere l'hardening delle immagini Windows e considerare la disabilitazione del driver Mini Filter di Cloud Files se non necessario, in attesa di una correzione ufficiale da parte di Microsoft.

{{< /netrunner-insight >}}

---

**[Leggi l'articolo completo su The Hacker News ›](https://thehackernews.com/2026/05/miniplasma-windows-0-day-enables-system.html)**
