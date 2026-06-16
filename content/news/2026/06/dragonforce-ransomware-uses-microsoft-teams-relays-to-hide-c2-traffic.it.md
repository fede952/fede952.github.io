---
title: "Il ransomware DragonForce utilizza i relay di Microsoft Teams per nascondere il traffico C2"
date: "2026-06-16T12:10:12Z"
original_date: "2026-06-16T10:18:48"
lang: "it"
translationKey: "dragonforce-ransomware-uses-microsoft-teams-relays-to-hide-c2-traffic"
author: "NewsBot (Validated by Federico Sella)"
description: "Il ransomware DragonForce distribuisce il malware personalizzato 'Backdoor.Turn' per occultare il traffico di comando e controllo all'interno dell'infrastruttura di relay di Microsoft Teams."
original_url: "https://www.bleepingcomputer.com/news/security/ransomware-gang-abuses-microsoft-teams-relays-to-hide-malicious-traffic/"
source: "BleepingComputer"
severity: "High"
target: "Infrastruttura di relay di Microsoft Teams"
cve: null
cvss: null
kev: null
tags: ["news", "cybersecurity"]
news-categories: ["cybersecurity"]
layout: "news"
draft: false
---

Il ransomware DragonForce distribuisce il malware personalizzato 'Backdoor.Turn' per occultare il traffico di comando e controllo all'interno dell'infrastruttura di relay di Microsoft Teams.

{{< cyber-report severity="High" source="BleepingComputer" target="Infrastruttura di relay di Microsoft Teams" >}}

Il gruppo ransomware DragonForce è stato osservato utilizzare un malware personalizzato chiamato 'Backdoor.Turn' per nascondere il traffico di comando e controllo (C2) all'interno dell'infrastruttura di relay di Microsoft Teams. Questa tecnica consente agli aggressori di mescolare le comunicazioni malevole con il traffico legittimo di Teams, rendendo più difficile il rilevamento per i difensori di rete.

{{< ad-banner >}}

Abusando dei relay di Microsoft Teams, la gang ransomware può bypassare i controlli di sicurezza di rete tradizionali che potrebbero non esaminare il traffico verso servizi fidati. Il malware probabilmente sfrutta le API o i protocolli di Teams per incanalare i dati C2, eludendo il rilevamento basato su firme e consentendo un accesso persistente alle reti compromesse.

Le organizzazioni che utilizzano Microsoft Teams dovrebbero monitorare modelli insoliti di traffico in uscita verso gli endpoint di Teams e considerare l'implementazione di ispezioni aggiuntive per i tunnel crittografati. Questo incidente evidenzia la crescente tendenza dei gruppi ransomware ad adottare tecniche di living-off-the-land e abuso di servizi fidati per eludere il rilevamento.

{{< netrunner-insight >}}

Per gli analisti SOC, ciò sottolinea la necessità di stabilire una baseline del traffico normale di Teams e di generare alert per anomalie come volumi di dati inaspettati o connessioni a endpoint di Teams non standard. I team DevSecOps dovrebbero rivedere le autorizzazioni di integrazione di Teams e limitare l'accesso API non necessario per ridurre la superficie d'attacco per l'abuso dei relay.

{{< /netrunner-insight >}}

---

**[Leggi l'articolo completo su BleepingComputer ›](https://www.bleepingcomputer.com/news/security/ransomware-gang-abuses-microsoft-teams-relays-to-hide-malicious-traffic/)**
