---
title: "CISA aggiunge la vulnerabilità RCE di PTC Windchill al KEV in mezzo ad attacchi attivi di web shell"
date: "2026-06-27T09:25:09Z"
original_date: "2026-06-26T12:31:56"
lang: "it"
translationKey: "cisa-adds-ptc-windchill-rce-flaw-to-kev-amid-active-web-shell-attacks"
author: "NewsBot (Validated by Federico Sella)"
description: "CISA aggiunge una vulnerabilità critica di esecuzione remota di codice in PTC Windchill PDMlink e FlexPLM al suo catalogo Known Exploited Vulnerabilities a causa di sfruttamento attivo."
original_url: "https://thehackernews.com/2026/06/cisa-adds-exploited-ptc-windchill-rce.html"
source: "The Hacker News"
severity: "Critical"
target: "PTC Windchill PDMlink e FlexPLM"
cve: null
cvss: null
kev: true
tags: ["news", "cybersecurity"]
news-categories: ["cybersecurity"]
layout: "news"
draft: false
---

CISA aggiunge una vulnerabilità critica di esecuzione remota di codice in PTC Windchill PDMlink e FlexPLM al suo catalogo Known Exploited Vulnerabilities a causa di sfruttamento attivo.

{{< cyber-report severity="Critical" source="The Hacker News" target="PTC Windchill PDMlink e FlexPLM" kev="true" >}}

La Cybersecurity and Infrastructure Security Agency (CISA) degli Stati Uniti ha aggiunto una vulnerabilità critica di esecuzione remota di codice che interessa PTC Windchill PDMlink e PTC FlexPLM al suo catalogo Known Exploited Vulnerabilities (KEV). La decisione segue prove di sfruttamento attivo, con segnalazioni di attacchi in corso di web shell contro questi sistemi enterprise di Product Data Management (PDM) e Product Lifecycle Management (PLM).

{{< ad-banner >}}

Sebbene l'identificatore CVE specifico non sia stato divulgato nell'annuncio, la vulnerabilità è descritta come un difetto RCE critico che potrebbe consentire agli aggressori di eseguire codice arbitrario sui sistemi interessati. Le organizzazioni che utilizzano questi prodotti sono invitate a dare priorità all'applicazione delle patch e a rivedere i propri ambienti per individuare segni di compromissione, poiché lo sfruttamento potrebbe portare alla completa compromissione del sistema.

Il catalogo KEV di CISA funge da direttiva operativa vincolante per le agenzie federali, richiedendo la correzione entro tempistiche specifiche. Le organizzazioni del settore privato sono fortemente invitate a considerare questa minaccia come ad alta priorità e a implementare mitigazioni come la segmentazione della rete e il monitoraggio di attività anomale di web shell.

{{< netrunner-insight >}}

Per gli analisti SOC, dare priorità alla caccia di indicatori di web shell sui server Windchill esposti—cercare processi figlio insoliti generati dall'applicazione o connessioni in uscita verso IP sconosciuti. I team DevSecOps dovrebbero applicare immediatamente le patch disponibili e considerare l'implementazione di patch virtuali o regole WAF se l'applicazione delle patch è ritardata. Questo è un promemoria che i sistemi PLM, spesso trascurati nella gestione delle patch, sono obiettivi attraenti per i gruppi ransomware.

{{< /netrunner-insight >}}

---

**[Leggi l'articolo completo su The Hacker News ›](https://thehackernews.com/2026/06/cisa-adds-exploited-ptc-windchill-rce.html)**
