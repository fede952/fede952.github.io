---
title: "Vulnerabilità delle telecamere Milesight consentono l'esecuzione remota di codice"
date: "2026-04-29T07:21:59Z"
original_date: "2026-04-23T12:00:00"
lang: "it"
translationKey: "milesight-camera-vulnerabilities-enable-remote-code-execution"
author: "NewsBot (Validated by Federico Sella)"
description: "CISA mette in guardia su diversi modelli di telecamere Milesight affetti da vulnerabilità critiche (CVE-2026-28747, ecc.) che potrebbero portare a crash del dispositivo o esecuzione remota di codice."
original_url: "https://www.cisa.gov/news-events/ics-advisories/icsa-26-113-03"
source: "CISA"
severity: "Critical"
target: "Telecamere IP Milesight"
cve: "CVE-2026-28747"
cvss: null
kev: null
tags: ["news", "cybersecurity"]
news-categories: ["cybersecurity"]
layout: "news"
draft: false
---

CISA mette in guardia su diversi modelli di telecamere Milesight affetti da vulnerabilità critiche (CVE-2026-28747, ecc.) che potrebbero portare a crash del dispositivo o esecuzione remota di codice.

{{< cyber-report severity="Critical" source="CISA" target="Telecamere IP Milesight" cve="CVE-2026-28747" >}}

CISA ha pubblicato un avviso (ICSA-26-113-03) che descrive in dettaglio molteplici vulnerabilità che interessano un'ampia gamma di modelli di telecamere Milesight. I difetti, identificati come CVE-2026-28747, CVE-2026-27785, CVE-2026-32644, CVE-2026-32649 e CVE-2026-20766, riguardano versioni firmware in diverse linee di prodotti, tra cui MS-Cxx63-PD, MS-Cxx64-xPD e altre. Un exploit riuscito potrebbe consentire a un attaccante di causare il crash del dispositivo o ottenere l'esecuzione remota di codice.

{{< ad-banner >}}

I modelli interessati coprono diverse serie, con versioni firmware fino a 51.7.0.77-r12, 3x.8.0.3-r11, 63.8.0.4-r3 e altre. Data la natura critica dell'esecuzione remota di codice, queste vulnerabilità rappresentano un rischio significativo per le organizzazioni che utilizzano telecamere Milesight in implementazioni di sorveglianza o IoT. CISA raccomanda agli utenti di applicare le patch disponibili e seguire le indicazioni del fornitore per mitigare l'esposizione.

Sebbene nell'avviso non siano forniti punteggi CVSS né prove di sfruttamento attivo, il potenziale di compromissione del dispositivo e di intrusione nella rete richiede un'attenzione immediata. I team di sicurezza dovrebbero inventariare i modelli di telecamere interessati, segmentare i dispositivi IoT dalle reti critiche e dare priorità agli aggiornamenti firmware.

{{< netrunner-insight >}}

Per gli analisti SOC, monitorare il traffico anomalo proveniente dalle sottoreti delle telecamere e assicurarsi che questi dispositivi siano isolati. Gli ingegneri DevSecOps dovrebbero accelerare l'applicazione delle patch a tutte le telecamere Milesight, poiché le vulnerabilità di esecuzione remota di codice nei dispositivi periferici diventano spesso punti di ingresso per movimenti laterali. Trattare queste CVE come critiche fino a quando le patch del fornitore non saranno verificate.

{{< /netrunner-insight >}}

---

**[Leggi l'articolo completo su CISA ›](https://www.cisa.gov/news-events/ics-advisories/icsa-26-113-03)**
