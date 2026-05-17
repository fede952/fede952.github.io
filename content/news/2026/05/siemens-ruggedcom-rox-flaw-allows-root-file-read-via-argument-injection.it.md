---
title: "Vulnerabilità in Siemens Ruggedcom ROX consente lettura di file root tramite injection di argomenti"
date: "2026-05-17T09:01:07Z"
original_date: "2026-05-14T12:00:00"
lang: "it"
translationKey: "siemens-ruggedcom-rox-flaw-allows-root-file-read-via-argument-injection"
author: "NewsBot (Validated by Federico Sella)"
description: "CISA avverte di CVE-2025-40948 che colpisce diversi dispositivi Ruggedcom ROX. Un attaccante remoto autenticato può leggere file arbitrari con privilegi di root. Aggiornare alla versione 2.17.1 o successiva."
original_url: "https://www.cisa.gov/news-events/ics-advisories/icsa-26-134-02"
source: "CISA"
severity: "Medium"
target: "Dispositivi Siemens Ruggedcom ROX"
cve: "CVE-2025-40948"
cvss: 6.8
kev: null
tags: ["news", "cybersecurity"]
news-categories: ["cybersecurity"]
layout: "news"
draft: false
---

CISA avverte di CVE-2025-40948 che colpisce diversi dispositivi Ruggedcom ROX. Un attaccante remoto autenticato può leggere file arbitrari con privilegi di root. Aggiornare alla versione 2.17.1 o successiva.

{{< cyber-report severity="Medium" source="CISA" target="Dispositivi Siemens Ruggedcom ROX" cve="CVE-2025-40948" cvss="6.8" >}}

I dispositivi della serie Siemens Ruggedcom ROX sono affetti da una vulnerabilità di controllo degli accessi improprio (CVE-2025-40948) che consente a un attaccante remoto autenticato di leggere file arbitrari con privilegi di root dal sistema operativo sottostante. Il difetto deriva da una convalida impropria dell'input nell'interfaccia JSON-RPC del server web, consentendo l'iniezione di argomenti.

{{< ad-banner >}}

I seguenti prodotti sono vulnerabili: RUGGEDCOM ROX MX5000, MX5000RE, RX1400, RX1500, RX1501, RX1510, RX1511, RX1512, RX1524, RX1536 e RX5000, tutti con versioni precedenti alla 2.17.1. Siemens ha rilasciato aggiornamenti per risolvere il problema e raccomanda l'applicazione immediata delle patch.

Con un punteggio CVSS v3 di 6.8, questa vulnerabilità è classificata come gravità Media. Il vettore d'attacco è basato sulla rete, richiede bassi privilegi e nessuna interazione dell'utente. Considerando i settori infrastrutturali critici (ad esempio, la produzione critica) in cui questi dispositivi sono distribuiti, lo sfruttamento potrebbe portare a una significativa divulgazione di informazioni.

{{< netrunner-insight >}}

Per gli analisti SOC: dare priorità all'applicazione delle patch sui dispositivi Ruggedcom ROX nel proprio ambiente, specialmente quelli esposti a reti non fidate. La natura autenticata dell'exploit riduce il rischio immediato ma non lo elimina: gli attaccanti che compromettono un account a bassi privilegi possono escalare fino all'accesso completo ai file di root. I team DevSecOps dovrebbero rivedere l'indurimento degli endpoint JSON-RPC e considerare la segmentazione della rete per limitare l'esposizione.

{{< /netrunner-insight >}}

---

**[Leggi l'articolo completo su CISA ›](https://www.cisa.gov/news-events/ics-advisories/icsa-26-134-02)**
