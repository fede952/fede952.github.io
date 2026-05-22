---
title: "Vulnerabilità nella ABB Terra AC Wallbox consentono l'esecuzione remota di codice"
date: "2026-05-22T10:24:17Z"
original_date: "2026-05-21T12:00:00"
lang: "it"
translationKey: "abb-terra-ac-wallbox-vulnerabilities-allow-remote-code-execution"
author: "NewsBot (Validated by Federico Sella)"
description: "CISA avverte di overflow di heap e stack in ABB Terra AC Wallbox (JP) ≤1.8.33; aggiornare alla versione 1.8.36 per mitigare CVE-2025-10504, CVE-2025-12142, CVE-2025-12143."
original_url: "https://www.cisa.gov/news-events/ics-advisories/icsa-26-141-05"
source: "CISA"
severity: "Medium"
target: "ABB Terra AC Wallbox (JP)"
cve: "CVE-2025-10504"
cvss: 6.1
kev: null
tags: ["news", "cybersecurity"]
news-categories: ["cybersecurity"]
layout: "news"
draft: false
---

CISA avverte di overflow di heap e stack in ABB Terra AC Wallbox (JP) ≤1.8.33; aggiornare alla versione 1.8.36 per mitigare CVE-2025-10504, CVE-2025-12142, CVE-2025-12143.

{{< cyber-report severity="Medium" source="CISA" target="ABB Terra AC Wallbox (JP)" cve="CVE-2025-10504" cvss="6.1" >}}

ABB ha divulgato diverse vulnerabilità che interessano la sua linea di prodotti Terra AC Wallbox (JP), in particolare le versioni fino alla 1.8.33 inclusa. I difetti includono un buffer overflow basato su heap (CVE-2025-10504), una copia di buffer senza controllo della dimensione dell'input (CVE-2025-12142) e un buffer overflow basato su stack (CVE-2025-12143). Lo sfruttamento riuscito potrebbe consentire a un attaccante di corrompere la memoria heap, portando potenzialmente al controllo remoto del dispositivo e a scritture non autorizzate nella memoria flash, alterando così il comportamento del firmware.

{{< ad-banner >}}

Le vulnerabilità hanno un punteggio base CVSS v3 di 6.1, indicando una gravità media. ABB ha rilasciato la versione firmware 1.8.36 per risolvere questi problemi. I prodotti sono distribuiti in tutto il mondo nel settore energetico e il fornitore raccomanda di applicare l'aggiornamento il prima possibile.

Sebbene non sia stato segnalato alcuno sfruttamento attivo, il potenziale di esecuzione remota di codice e manipolazione del firmware rende queste vulnerabilità critiche per gli operatori delle infrastrutture di ricarica per veicoli elettrici. Le organizzazioni dovrebbero dare priorità alla correzione dei dispositivi interessati, specialmente quelli esposti a reti non fidate.

{{< netrunner-insight >}}

Per gli analisti SOC, monitorare il traffico anomalo verso i dispositivi Terra AC Wallbox, in particolare operazioni di scrittura impreviste sulla memoria flash. Gli ingegneri DevSecOps dovrebbero imporre una rigorosa validazione degli input in qualsiasi protocollo personalizzato che comunichi con il caricabatterie e assicurarsi che gli aggiornamenti del firmware siano applicati tempestivamente. Dato il punteggio CVSS di 6.1, trattare queste vulnerabilità come priorità media ma con alto potenziale di impatto a causa del ruolo del dispositivo nelle infrastrutture energetiche critiche.

{{< /netrunner-insight >}}

---

**[Leggi l'articolo completo su CISA ›](https://www.cisa.gov/news-events/ics-advisories/icsa-26-141-05)**
