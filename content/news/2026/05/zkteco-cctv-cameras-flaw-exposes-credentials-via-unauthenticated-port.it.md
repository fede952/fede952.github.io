---
title: "Vulnerabilità nelle telecamere CCTV ZKTeco espone le credenziali tramite una porta non autenticata"
date: "2026-05-20T10:24:09Z"
original_date: "2026-05-19T12:00:00"
lang: "it"
translationKey: "zkteco-cctv-cameras-flaw-exposes-credentials-via-unauthenticated-port"
author: "NewsBot (Validated by Federico Sella)"
description: "CISA avverte di CVE-2026-8598 nelle telecamere CCTV ZKTeco, che consente il furto di credenziali tramite una porta non documentata. Patch disponibile nel firmware V5.0.1.2.20260421."
original_url: "https://www.cisa.gov/news-events/ics-advisories/icsa-26-139-04"
source: "CISA"
severity: "Critical"
target: "Telecamere CCTV ZKTeco"
cve: "CVE-2026-8598"
cvss: 9.1
kev: null
tags: ["news", "cybersecurity"]
news-categories: ["cybersecurity"]
layout: "news"
draft: false
---

CISA avverte di CVE-2026-8598 nelle telecamere CCTV ZKTeco, che consente il furto di credenziali tramite una porta non documentata. Patch disponibile nel firmware V5.0.1.2.20260421.

{{< cyber-report severity="Critical" source="CISA" target="Telecamere CCTV ZKTeco" cve="CVE-2026-8598" cvss="9.1" >}}

CISA ha pubblicato un advisory (ICSA-26-139-04) che descrive una vulnerabilità critica di bypass dell'autenticazione nelle telecamere CCTV ZKTeco. La falla, tracciata come CVE-2026-8598, riguarda una porta di esportazione della configurazione non documentata accessibile senza autenticazione. Lo sfruttamento riuscito potrebbe portare alla divulgazione di informazioni, inclusa l'acquisizione delle credenziali dell'account della telecamera.

{{< ad-banner >}}

La vulnerabilità interessa le versioni del firmware ZKTeco SSC335-GC2063-Face-0b77 Solution precedenti alla V5.0.1.2.20260421. Il punteggio base CVSS v3 è 9.1, indicando una gravità critica. I dispositivi interessati sono distribuiti in tutto il mondo in strutture commerciali, con il produttore con sede in Cina.

ZKTeco ha rilasciato una versione del firmware corretta, V5.0.1.2.20260421, per risolvere il problema. Si consiglia vivamente agli utenti di aggiornare immediatamente. La vulnerabilità è classificata come CWE-288 (Bypass dell'autenticazione tramite un percorso o canale alternativo).

{{< netrunner-insight >}}

Questo è un esempio classico di un'interfaccia di debug esposta che diventa una backdoor. Gli analisti SOC dovrebbero immediatamente scansionare la rete alla ricerca di telecamere ZKTeco e verificare le versioni del firmware. Per i DevSecOps, ciò sottolinea la necessità di disabilitare o firewallare le porte non documentate nelle build del firmware IoT. Considera qualsiasi telecamera con firmware inferiore a V5.0.1.2.20260421 come compromessa fino a prova contraria.

{{< /netrunner-insight >}}

---

**[Leggi l'articolo completo su CISA ›](https://www.cisa.gov/news-events/ics-advisories/icsa-26-139-04)**
