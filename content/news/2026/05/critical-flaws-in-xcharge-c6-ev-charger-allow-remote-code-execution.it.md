---
title: "Gravi vulnerabilità nel caricatore EV XCharge C6 consentono l'esecuzione remota di codice"
date: "2026-05-29T10:39:44Z"
original_date: "2026-05-28T12:00:00"
lang: "it"
translationKey: "critical-flaws-in-xcharge-c6-ev-charger-allow-remote-code-execution"
author: "NewsBot (Validated by Federico Sella)"
description: "CISA avverte di vulnerabilità non autenticate nei controller di ricarica EV XCharge C6, inclusa CVE-2026-9037, con un punteggio CVSS di 9.8."
original_url: "https://www.cisa.gov/news-events/ics-advisories/icsa-26-148-08"
source: "CISA"
severity: "Critical"
target: "Controller di ricarica EV XCharge C6"
cve: "CVE-2026-9037"
cvss: 9.8
kev: null
tags: ["news", "cybersecurity"]
news-categories: ["cybersecurity"]
layout: "news"
draft: false
---

CISA avverte di vulnerabilità non autenticate nei controller di ricarica EV XCharge C6, inclusa CVE-2026-9037, con un punteggio CVSS di 9.8.

{{< cyber-report severity="Critical" source="CISA" target="Controller di ricarica EV XCharge C6" cve="CVE-2026-9037" cvss="9.8" >}}

CISA ha pubblicato un advisory (ICSA-26-148-08) che descrive in dettaglio molteplici vulnerabilità critiche nei controller di ricarica per veicoli elettrici XCharge C6. I difetti includono un download di codice senza controllo di integrità (CWE-494), un buffer overflow basato su stack e l'inizializzazione di una risorsa con un'impostazione predefinita non sicura. Lo sfruttamento riuscito potrebbe consentire a un attaccante di ottenere diritti di amministratore o eseguire codice arbitrario sul dispositivo.

{{< ad-banner >}}

La vulnerabilità più grave, CVE-2026-9037, riguarda un meccanismo di aggiornamento del firmware che non convalida l'autenticità dei pacchetti firmware. Senza verifica della firma crittografica, un attaccante che può interferire o impersonare il canale di gestione potrebbe installare firmware non autorizzato, portando all'esecuzione di codice con privilegi elevati. Il punteggio CVSS v3 per questa vulnerabilità è 9.8, indicando una gravità critica.

XCharge ha distribuito un aggiornamento del firmware per tutti i caricatori interessati a partire dal 22 maggio 2026. Si consiglia agli utenti di assicurarsi che i propri dispositivi siano aggiornati e di contattare il supporto XCharge se necessario. Il prodotto interessato è ampiamente diffuso nel settore dei sistemi di trasporto in diversi paesi.

{{< netrunner-insight >}}

Per gli analisti SOC, dare priorità al monitoraggio delle interfacce di gestione dei caricatori XCharge C6 per accessi non autorizzati o richieste anomale di aggiornamento firmware. I team DevSecOps dovrebbero imporre la segmentazione di rete e applicare immediatamente la patch del fornitore, poiché la mancanza di controlli di integrità rende questi dispositivi un bersaglio primario per attacchi alla supply chain.

{{< /netrunner-insight >}}

---

**[Leggi l'articolo completo su CISA ›](https://www.cisa.gov/news-events/ics-advisories/icsa-26-148-08)**
