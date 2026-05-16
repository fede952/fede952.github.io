---
title: "Difetti di analisi dei file PAR in Siemens Solid Edge consentono l'esecuzione di codice"
date: "2026-05-16T08:48:36Z"
original_date: "2026-05-14T12:00:00"
lang: "it"
translationKey: "siemens-solid-edge-par-parsing-flaws-enable-code-execution"
author: "NewsBot (Validated by Federico Sella)"
description: "Due vulnerabilità di analisi dei file in Siemens Solid Edge SE2026 consentono agli aggressori di eseguire codice arbitrario tramite file PAR appositamente predisposti. Aggiornare alla versione V226.0 Update 5."
original_url: "https://www.cisa.gov/news-events/ics-advisories/icsa-26-134-03"
source: "CISA"
severity: "High"
target: "Siemens Solid Edge SE2026"
cve: "CVE-2026-44411"
cvss: 7.8
kev: null
tags: ["news", "cybersecurity"]
news-categories: ["cybersecurity"]
layout: "news"
draft: false
---

Due vulnerabilità di analisi dei file in Siemens Solid Edge SE2026 consentono agli aggressori di eseguire codice arbitrario tramite file PAR appositamente predisposti. Aggiornare alla versione V226.0 Update 5.

{{< cyber-report severity="High" source="CISA" target="Siemens Solid Edge SE2026" cve="CVE-2026-44411" cvss="7.8" >}}

Siemens Solid Edge SE2026 precedente all'Update 5 è affetto da due vulnerabilità di analisi dei file che possono essere attivate quando l'applicazione legge file PAR appositamente predisposti. I difetti includono un accesso a puntatore non inizializzato (CVE-2026-44411) e un buffer overflow basato su stack (CVE-2026-44412), entrambi potenzialmente in grado di consentire a un aggressore di causare il crash dell'applicazione o eseguire codice arbitrario nel contesto del processo corrente.

{{< ad-banner >}}

Le vulnerabilità hanno un punteggio base CVSS v3.1 di 7.8 (High) con il vettore AV:L/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H, che indica accesso locale, bassa complessità, nessun privilegio richiesto, necessità di interazione dell'utente e alto impatto su riservatezza, integrità e disponibilità. Siemens ha rilasciato la versione V226.0 Update 5 per risolvere questi problemi e raccomanda agli utenti di aggiornare immediatamente.

Considerando la diffusione mondiale nel settore manifatturiero critico, le organizzazioni che utilizzano Solid Edge dovrebbero dare priorità all'applicazione delle patch. Le vulnerabilità richiedono l'interazione dell'utente (apertura di un file PAR dannoso), pertanto si raccomanda anche la formazione sulla consapevolezza degli utenti come controllo compensativo.

{{< netrunner-insight >}}

Per gli analisti SOC, monitorare la gestione anomala di file PAR o crash nei processi di Solid Edge. Gli ingegneri DevSecOps dovrebbero applicare whitelist delle applicazioni e limitare i tipi di file per ridurre la superficie d'attacco. Poiché si tratta di vulnerabilità locali che dipendono dall'interazione dell'utente, le simulazioni di phishing e le regole di rilevamento degli endpoint per aperture sospette di file sono mitigazioni chiave.

{{< /netrunner-insight >}}

---

**[Leggi l'articolo completo su CISA ›](https://www.cisa.gov/news-events/ics-advisories/icsa-26-134-03)**
