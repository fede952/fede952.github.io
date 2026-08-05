---
title: "CISA aggiunge le vulnerabilità Langflow RCE, Tomcat e N-central al catalogo KEV"
date: "2026-08-05T09:30:51Z"
original_date: "2026-08-05T07:40:39"
lang: "it"
translationKey: "cisa-adds-langflow-rce-tomcat-n-central-flaws-to-kev-catalog"
slug: "cisa-adds-langflow-rce-tomcat-n-central-flaws-to-kev-catalog"
author: "NewsBot (Validated by Federico Sella)"
description: "CISA segnala tre vulnerabilità attivamente sfruttate, inclusa Langflow RCE (CVE-2026-9198) con CVSS 9.8, esortando a una patch immediata."
original_url: "https://thehackernews.com/2026/08/cisa-flags-langflow-rce-tomcat-and-n.html"
source: "The Hacker News"
severity: "Critical"
target: "Langflow, Apache Tomcat, N-central"
cve: "CVE-2026-9198"
cvss: 9.8
kev: true
tags: ["news", "cybersecurity"]
news-categories: ["cybersecurity"]
layout: "news"
draft: false
---

CISA segnala tre vulnerabilità attivamente sfruttate, inclusa Langflow RCE (CVE-2026-9198) con CVSS 9.8, esortando a una patch immediata.

{{< cyber-report severity="Critical" source="The Hacker News" target="Langflow, Apache Tomcat, N-central" cve="CVE-2026-9198" cvss="9.8" kev="true" >}}

La Cybersecurity and Infrastructure Security Agency (CISA) degli Stati Uniti ha aggiunto tre vulnerabilità al suo catalogo Known Exploited Vulnerabilities (KEV), citando prove di sfruttamento attivo. Tra queste figura CVE-2026-9198, una critica vulnerabilità di injection di codice in Langflow che consente a utenti non autenticati di ottenere piena esecuzione di codice remoto. La vulnerabilità ha un punteggio CVSS di 9.8, indicando un rischio grave.

{{< ad-banner >}}

Le altre due vulnerabilità riguardano Apache Tomcat e N-central, sebbene i dettagli specifici non siano forniti nel riepilogo. Il catalogo KEV di CISA è una lista prioritaria di vulnerabilità note per essere sfruttate, e le agenzie federali sono tenute a risolverle entro tempi specifici. Le organizzazioni sono esortate a rivedere il catalogo e applicare le patch immediatamente.

L'inclusione di queste vulnerabilità sottolinea l'importanza di una gestione tempestiva delle patch e dell'intelligence sulle minacce. I team di sicurezza dovrebbero monitorare gli indicatori di compromissione relativi a questi CVE e assicurarsi che i propri asset non siano esposti a vettori di attacco noti.

{{< netrunner-insight >}}

Per gli analisti SOC, dare priorità al monitoraggio dei tentativi di sfruttamento contro Langflow, Tomcat e N-central, poiché ora sono bersagli attivi confermati. DevSecOps dovrebbe accelerare le patch, soprattutto per le istanze esposte a Internet, e considerare l'implementazione di regole di rilevamento aggiuntive per l'attività post-sfruttamento. Dato il punteggio CVSS critico, trattare CVE-2026-9198 come un rischio di prim'ordine e verificare che non si sia verificato alcun accesso non autorizzato.

{{< /netrunner-insight >}}

---

**[Leggi l'articolo completo su The Hacker News ›](https://thehackernews.com/2026/08/cisa-flags-langflow-rce-tomcat-and-n.html)**
