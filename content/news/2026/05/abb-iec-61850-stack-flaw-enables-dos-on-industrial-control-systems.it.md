---
title: "Difetto nello Stack IEC 61850 di ABB Consente DoS sui Sistemi di Controllo Industriale"
date: "2026-05-01T09:03:14Z"
original_date: "2026-04-30T12:00:00"
lang: "it"
translationKey: "abb-iec-61850-stack-flaw-enables-dos-on-industrial-control-systems"
author: "NewsBot (Validated by Federico Sella)"
description: "CISA avverte di una vulnerabilità segnalata privatamente nell'implementazione IEC 61850 MMS di ABB che interessa i prodotti System 800xA e Symphony Plus, causando guasti ai dispositivi e denial-of-service."
original_url: "https://www.cisa.gov/news-events/ics-advisories/icsa-26-120-01"
source: "CISA"
severity: "High"
target: "ABB System 800xA, Symphony Plus IEC 61850"
cve: null
cvss: null
kev: null
tags: ["news", "cybersecurity"]
news-categories: ["cybersecurity"]
layout: "news"
draft: false
---

CISA avverte di una vulnerabilità segnalata privatamente nell'implementazione IEC 61850 MMS di ABB che interessa i prodotti System 800xA e Symphony Plus, causando guasti ai dispositivi e denial-of-service.

{{< cyber-report severity="High" source="CISA" target="ABB System 800xA, Symphony Plus IEC 61850" >}}

CISA ha emesso un avviso (ICSA-26-120-01) riguardante una vulnerabilità nell'implementazione da parte di ABB dello stack di comunicazione IEC 61850 per applicazioni client MMS. Il difetto interessa diversi prodotti delle linee System 800xA e Symphony Plus, inclusi AC800M CI868, Symphony Plus SD Series CI850, PM 877 e S+ Operations. Lo sfruttamento richiede l'accesso preventivo alla rete IEC 61850 del sito.

{{< ad-banner >}}

Uno sfruttamento riuscito causa un guasto del dispositivo sui moduli PM 877, CI850 e CI868, rendendo necessario un riavvio manuale. Per i nodi S+ Operations, l'attacco blocca il driver di comunicazione IEC 61850, portando a una condizione di denial-of-service se ripetuto. Tuttavia, la disponibilità e la funzionalità complessiva del nodo rimangono inalterate e la comunicazione del protocollo GOOSE non viene influenzata. Anche System 800xA IEC61850 Connect non è vulnerabile.

Le versioni firmware interessate coprono diversi rami, inclusi S+ Operations fino alla 6.2.0006.0 e varie release di PM 877. Nell'avviso non sono stati forniti né un identificatore CVE né un punteggio CVSS. Le organizzazioni che utilizzano questi prodotti dovrebbero esaminare l'avviso e applicare mitigazioni, come la segmentazione di rete e i controlli di accesso, per limitare l'esposizione alla rete IEC 61850.

{{< netrunner-insight >}}

Questa vulnerabilità sottolinea l'importanza della segmentazione di rete negli ambienti OT. Poiché lo sfruttamento richiede l'accesso alla rete IEC 61850, isolare tale rete dalla rete IT aziendale e da Internet è fondamentale. Gli analisti SOC dovrebbero monitorare il traffico IEC 61850 anomalo, mentre gli ingegneri DevSecOps dovrebbero dare priorità alla patch e considerare l'implementazione di sistemi di rilevamento delle intrusioni per anomalie nel protocollo MMS.

{{< /netrunner-insight >}}

---

**[Leggi l'articolo completo su CISA ›](https://www.cisa.gov/news-events/ics-advisories/icsa-26-120-01)**
