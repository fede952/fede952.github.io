---
title: "L'FBI sequestra il servizio proxy NetNut e l'infrastruttura del botnet Popa"
date: "2026-07-04T09:20:04Z"
original_date: "2026-07-02T19:27:33"
lang: "it"
translationKey: "fbi-seizes-netnut-proxy-service-and-popa-botnet-infrastructure"
author: "NewsBot (Validated by Federico Sella)"
description: "L'FBI ha sequestrato i domini collegati a NetNut, un servizio proxy residenziale legato al botnet Popa di 2 milioni di dispositivi compromessi, a seguito di un'inchiesta giornalistica."
original_url: "https://krebsonsecurity.com/2026/07/fbi-seizes-netnut-proxy-platform-popa-botnet/"
source: "Krebs on Security"
severity: "High"
target: "Servizio proxy residenziale NetNut e botnet Popa"
cve: null
cvss: null
kev: null
tags: ["news", "cybersecurity"]
news-categories: ["cybersecurity"]
layout: "news"
draft: false
---

L'FBI ha sequestrato i domini collegati a NetNut, un servizio proxy residenziale legato al botnet Popa di 2 milioni di dispositivi compromessi, a seguito di un'inchiesta giornalistica.

{{< cyber-report severity="High" source="Krebs on Security" target="Servizio proxy residenziale NetNut e botnet Popa" >}}

L'FBI, in coordinamento con partner del settore, ha sequestrato centinaia di domini associati a NetNut, un servizio proxy residenziale gestito dalla società israeliana quotata in borsa Alarum Technologies (NASDAQ: ALAR). L'azione fa seguito a un rapporto di KrebsOnSecurity che collegava NetNut al botnet Popa, una rete di almeno due milioni di dispositivi compromessi senza il consenso degli utenti.

{{< ad-banner >}}

Il botnet Popa sfrutta i dispositivi infetti per instradare il traffico attraverso l'infrastruttura proxy di NetNut, consentendo attività dannose come credential stuffing, frodi pubblicitarie e furto di account. Il sequestro interrompe sia il servizio proxy che le capacità di comando e controllo del botnet.

Questa operazione evidenzia la tendenza crescente delle forze dell'ordine a prendere di mira i servizi proxy che facilitano il cybercrimine. Le organizzazioni dovrebbero rivedere il proprio traffico di rete per individuare connessioni verso i domini sequestrati e monitorare eventuali attività residue del botnet.

{{< netrunner-insight >}}

Per gli analisti SOC, questo smantellamento sottolinea l'importanza di monitorare gli intervalli IP dei proxy residenziali nei feed di intelligence sulle minacce. I team DevSecOps dovrebbero verificare eventuali integrazioni con servizi proxy di terze parti e garantire l'implementazione di robusti meccanismi di rilevamento dei botnet, poiché i residui di Popa potrebbero persistere in infrastrutture alternative.

{{< /netrunner-insight >}}

---

**[Leggi l'articolo completo su Krebs on Security ›](https://krebsonsecurity.com/2026/07/fbi-seizes-netnut-proxy-platform-popa-botnet/)**
