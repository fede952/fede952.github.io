---
title: "CISA avverte di una falla in Siemens Opcenter RDnL tramite ActiveMQ Artemis con autenticazione mancante"
date: "2026-05-17T08:59:55Z"
original_date: "2026-05-14T12:00:00"
lang: "it"
translationKey: "cisa-warns-of-siemens-opcenter-rdnl-flaw-via-activemq-artemis-missing-auth"
author: "NewsBot (Validated by Federico Sella)"
description: "Siemens Opcenter RDnL è affetto da CVE-2026-27446, una vulnerabilità di autenticazione mancante in ActiveMQ Artemis che consente a un attaccante adiacente non autenticato di iniettare o esfiltrare messaggi."
original_url: "https://www.cisa.gov/news-events/ics-advisories/icsa-26-134-09"
source: "CISA"
severity: "High"
target: "Siemens Opcenter RDnL"
cve: "CVE-2026-27446"
cvss: 7.1
kev: null
tags: ["news", "cybersecurity"]
news-categories: ["cybersecurity"]
layout: "news"
draft: false
---

Siemens Opcenter RDnL è affetto da CVE-2026-27446, una vulnerabilità di autenticazione mancante in ActiveMQ Artemis che consente a un attaccante adiacente non autenticato di iniettare o esfiltrare messaggi.

{{< cyber-report severity="High" source="CISA" target="Siemens Opcenter RDnL" cve="CVE-2026-27446" cvss="7.1" >}}

CISA ha pubblicato un advisory (ICSA-26-134-09) che descrive una vulnerabilità di autenticazione mancante per funzioni critiche in Apache ActiveMQ Artemis, che interessa Siemens Opcenter RDnL. La falla, tracciata come CVE-2026-27446 con un punteggio CVSS v3 di 7.1, consente a un attaccante non autenticato nella rete adiacente di forzare un broker target a stabilire una connessione Core federation in uscita verso un broker rogue. Ciò può portare all'iniezione di messaggi in qualsiasi coda o all'esfiltrazione di messaggi da qualsiasi coda tramite il broker rogue.

{{< ad-banner >}}

La vulnerabilità impatta tutte le versioni di Siemens Opcenter RDnL. Sebbene l'impatto sull'integrità sia considerato basso a causa della mancanza di funzionalità di auto-aggiornamento e dell'assenza di informazioni riservate nei messaggi, l'impatto sulla disponibilità e il potenziale di manipolazione dei messaggi rimangono significativi. ActiveMQ Artemis ha rilasciato una correzione e Siemens raccomanda di aggiornare immediatamente all'ultima versione.

Considerando la distribuzione mondiale nel settore manifatturiero critico, le organizzazioni che utilizzano Opcenter RDnL dovrebbero dare priorità alla patch. Il vettore di attacco sulla rete adiacente riduce l'esposizione immediata ma rappresenta comunque un rischio in ambienti segmentati. I blue team dovrebbero monitorare connessioni Core federation inusuali e attività di broker rogue.

{{< netrunner-insight >}}

Per gli analisti SOC, monitorare connessioni Core federation in uscita inaspettate dai broker ActiveMQ Artemis, poiché questo è l'indicatore principale di sfruttamento. I team DevSecOps dovrebbero aggiornare immediatamente all'ultima versione di ActiveMQ Artemis e limitare l'accesso al protocollo Core solo a reti fidate. Questa falla sottolinea il rischio dell'autenticazione mancante nei componenti middleware, anche quando l'impatto immediato sembra basso.

{{< /netrunner-insight >}}

---

**[Leggi l'articolo completo su CISA ›](https://www.cisa.gov/news-events/ics-advisories/icsa-26-134-09)**
