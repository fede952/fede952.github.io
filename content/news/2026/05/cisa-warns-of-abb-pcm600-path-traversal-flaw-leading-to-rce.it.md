---
title: "CISA avverte di una falla di path traversal in ABB PCM600 che porta a RCE"
date: "2026-05-01T08:59:15Z"
original_date: "2026-04-30T12:00:00"
lang: "it"
translationKey: "cisa-warns-of-abb-pcm600-path-traversal-flaw-leading-to-rce"
author: "NewsBot (Validated by Federico Sella)"
description: "Le versioni da 1.5 a 2.13 di ABB PCM600 sono vulnerabili a una falla di path traversal (CVE-2018-1002208) che potrebbe consentire l'esecuzione di codice arbitrario. Aggiornare alla versione 2.14."
original_url: "https://www.cisa.gov/news-events/ics-advisories/icsa-26-120-02"
source: "CISA"
severity: "Medium"
target: "ABB PCM600"
cve: "CVE-2018-1002208"
cvss: null
kev: null
tags: ["news", "cybersecurity"]
news-categories: ["cybersecurity"]
layout: "news"
draft: false
---

Le versioni da 1.5 a 2.13 di ABB PCM600 sono vulnerabili a una falla di path traversal (CVE-2018-1002208) che potrebbe consentire l'esecuzione di codice arbitrario. Aggiornare alla versione 2.14.

{{< cyber-report severity="Medium" source="CISA" target="ABB PCM600" cve="CVE-2018-1002208" >}}

CISA ha pubblicato un advisory (ICSA-26-120-02) che descrive una vulnerabilità in ABB PCM600, un gestore di IED per protezione e controllo. La falla, identificata come CVE-2018-1002208, risiede nella libreria SharpZip.dll e comporta una limitazione impropria di un pathname a una directory ristretta (path traversal). Un attacco riuscito potrebbe consentire a un aggressore di inviare messaggi appositamente predisposti al nodo di sistema, provocando l'esecuzione di codice arbitrario.

{{< ad-banner >}}

Le versioni interessate del prodotto sono PCM600 dalla 1.5 fino alla 2.13 inclusa. ABB ha rilasciato la versione 2.14 per risolvere il problema. Tuttavia, si noti che i relè di protezione RE_630 non sono compatibili con PCM600 2.14, quindi gli utenti di versioni precedenti con RE_630 devono fare affidamento sulle difese a livello di sistema come indicato nelle Raccomandazioni Generali di Sicurezza di ABB.

L'advisory sottolinea che il prodotto è distribuito in tutto il mondo nel settore della produzione critica. Sebbene non venga fornito un punteggio CVSS nell'advisory, il potenziale della vulnerabilità per l'esecuzione di codice richiede una correzione tempestiva ove possibile. Le organizzazioni dovrebbero dare priorità all'aggiornamento a PCM600 2.14 e implementare la segmentazione di rete e i controlli di accesso per i sistemi che non possono essere aggiornati immediatamente.

{{< netrunner-insight >}}

Questa vulnerabilità di path traversal in ABB PCM600 ricorda che dipendenze legacy come SharpZip.dll possono introdurre rischi. Per gli analisti SOC, monitorare il traffico di rete anomalo verso i nodi PCM600, in particolare messaggi appositamente predisposti che potrebbero indicare tentativi di sfruttamento. Gli ingegneri DevSecOps dovrebbero inventariare tutte le istanze di PCM600 e pianificare gli aggiornamenti alla versione 2.14, assicurando al contempo che la compatibilità con i relè RE_630 sia gestita tramite controlli compensativi.

{{< /netrunner-insight >}}

---

**[Leggi l'articolo completo su CISA ›](https://www.cisa.gov/news-events/ics-advisories/icsa-26-120-02)**
