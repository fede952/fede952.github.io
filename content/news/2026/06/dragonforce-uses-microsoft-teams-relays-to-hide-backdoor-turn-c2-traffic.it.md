---
title: "DragonForce utilizza i relay di Microsoft Teams per nascondere il traffico C2 di Backdoor.Turn"
date: "2026-06-19T11:15:07Z"
original_date: "2026-06-18T13:30:07"
lang: "it"
translationKey: "dragonforce-uses-microsoft-teams-relays-to-hide-backdoor-turn-c2-traffic"
author: "NewsBot (Validated by Federico Sella)"
description: "Il gruppo ransomware DragonForce distribuisce un RAT personalizzato basato su Go chiamato Backdoor.Turn, occultando il traffico C2 all'interno dei relay di Microsoft Teams, prendendo di mira una grande azienda di servizi statunitense."
original_url: "https://thehackernews.com/2026/06/dragonforce-hackers-abuse-microsoft.html"
source: "The Hacker News"
severity: "High"
target: "Grande azienda di servizi statunitense"
cve: null
cvss: null
kev: null
tags: ["news", "cybersecurity"]
news-categories: ["cybersecurity"]
layout: "news"
draft: false
---

Il gruppo ransomware DragonForce distribuisce un RAT personalizzato basato su Go chiamato Backdoor.Turn, occultando il traffico C2 all'interno dei relay di Microsoft Teams, prendendo di mira una grande azienda di servizi statunitense.

{{< cyber-report severity="High" source="The Hacker News" target="Grande azienda di servizi statunitense" >}}

Attori di minaccia associati al gruppo ransomware DragonForce sono stati osservati utilizzare un trojan ad accesso remoto (RAT) personalizzato basato su Go chiamato Backdoor.Turn per nascondere il traffico di comando e controllo (C2) all'interno dell'infrastruttura di relay di Microsoft Teams. Il backdoor è stato distribuito contro una grande azienda di servizi statunitense, secondo i risultati di Symantec e Carbon Black, di proprietà di Broadcom.

{{< ad-banner >}}

Sfruttando i relay legittimi di Microsoft Teams, gli aggressori possono mescolare il traffico malevolo con le normali comunicazioni aziendali, rendendo più difficile il rilevamento per i difensori di rete. Il RAT basato su Go fornisce agli aggressori accesso persistente e la capacità di eseguire comandi, esfiltrare dati e distribuire payload aggiuntivi.

Questa tecnica evidenzia l'evoluzione delle tattiche dei gruppi ransomware per eludere gli strumenti tradizionali di monitoraggio di rete. Le organizzazioni che utilizzano Microsoft Teams dovrebbero rivedere le proprie configurazioni di sicurezza e monitorare modelli di traffico relay anomali.

{{< netrunner-insight >}}

Gli analisti SOC dovrebbero monitorare il traffico insolito dei relay di Microsoft Teams, specialmente da endpoint non standard o durante orari non lavorativi. I team DevSecOps dovrebbero applicare un allowlisting rigoroso delle applicazioni e ispezionare il traffico di Teams alla ricerca di tunnel crittografati che potrebbero indicare comunicazioni C2. Questo attacco sottolinea la necessità di principi di zero-trust anche per piattaforme di collaborazione fidate.

{{< /netrunner-insight >}}

---

**[Leggi l'articolo completo su The Hacker News ›](https://thehackernews.com/2026/06/dragonforce-hackers-abuse-microsoft.html)**
