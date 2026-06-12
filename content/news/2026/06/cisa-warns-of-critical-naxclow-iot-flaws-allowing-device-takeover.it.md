---
title: "CISA mette in guardia da vulnerabilità critiche Naxclow IoT che consentono il controllo dei dispositivi"
date: "2026-06-12T10:59:58Z"
original_date: "2026-06-11T12:00:00"
lang: "it"
translationKey: "cisa-warns-of-critical-naxclow-iot-flaws-allowing-device-takeover"
author: "NewsBot (Validated by Federico Sella)"
description: "Molteplici vulnerabilità nella piattaforma IoT Naxclow, inclusa CVE-2026-42947, consentono il dirottamento dei dispositivi e la raccolta di credenziali. Colpisce videocitofoni intelligenti e hub domestici."
original_url: "https://www.cisa.gov/news-events/ics-advisories/icsa-26-162-02"
source: "CISA"
severity: "Critical"
target: "Dispositivi della piattaforma IoT Naxclow"
cve: "CVE-2026-42947"
cvss: 9.8
kev: null
tags: ["news", "cybersecurity"]
news-categories: ["cybersecurity"]
layout: "news"
draft: false
---

Molteplici vulnerabilità nella piattaforma IoT Naxclow, inclusa CVE-2026-42947, consentono il dirottamento dei dispositivi e la raccolta di credenziali. Colpisce videocitofoni intelligenti e hub domestici.

{{< cyber-report severity="Critical" source="CISA" target="Dispositivi della piattaforma IoT Naxclow" cve="CVE-2026-42947" cvss="9.8" >}}

CISA ha emesso un avviso (ICSA-26-162-02) che descrive molteplici vulnerabilità nella piattaforma IoT Naxclow, che interessano prodotti come Smart Doorbell X3, X Smart Home, V720 e ix cam. La falla più grave, CVE-2026-42947, ha un punteggio CVSS di 9.8 e comporta un bypass dell'autorizzazione tramite una chiave controllata dall'utente, consentendo a un utente malintenzionato di riprodurre una sequenza di conferma e associazione per riassegnare silenziosamente un dispositivo a un account arbitrario senza interazione da parte dell'utente.

{{< ad-banner >}}

Ulteriori debolezze includono controlli di autorizzazione mancanti, uso di chiavi crittografiche hard-coded, generazione di identificatori prevedibili e inserimento di informazioni sensibili in file accessibili esternamente. Lo sfruttamento riuscito potrebbe consentire l'impersonificazione del dispositivo, l'intercettazione o la manipolazione delle comunicazioni, la raccolta su larga scala di credenziali e l'accesso non autorizzato ai sistemi interessati.

Le vulnerabilità interessano tutte le versioni dei prodotti elencati e i dispositivi sono distribuiti in tutto il mondo in strutture commerciali. Naxclow, con sede in Cina, non ha ancora rilasciato patch. Le organizzazioni che utilizzano questi dispositivi dovrebbero implementare immediatamente la segmentazione della rete e il monitoraggio per rilevare attività anomale di associazione dei dispositivi.

{{< netrunner-insight >}}

Questo è un classico incubo IoT della supply chain: chiavi hard-coded, ID prevedibili e un flusso di onboarding riproducibile. I team SOC dovrebbero cercare riassegnazioni inaspettate dei dispositivi nei log e considerare l'isolamento dei dispositivi Naxclow su una VLAN separata fino all'arrivo delle patch. DevSecOps deve spingere per l'identità crittografica del dispositivo e l'autenticazione reciproca nell'onboarding IoT.

{{< /netrunner-insight >}}

---

**[Leggi l'articolo completo su CISA ›](https://www.cisa.gov/news-events/ics-advisories/icsa-26-162-02)**
