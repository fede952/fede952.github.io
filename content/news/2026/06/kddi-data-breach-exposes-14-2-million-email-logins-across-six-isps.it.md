---
title: "Violazione dati KDDI espone 14,2 milioni di accessi email su sei ISP"
date: "2026-06-29T11:56:07Z"
original_date: "2026-06-28T14:13:46"
lang: "it"
translationKey: "kddi-data-breach-exposes-14-2-million-email-logins-across-six-isps"
author: "NewsBot (Validated by Federico Sella)"
description: "Il colosso giapponese delle telecomunicazioni KDDI rivela una violazione del sistema email che coinvolge altri cinque ISP, compromettendo fino a 14,2 milioni di credenziali utente."
original_url: "https://www.bleepingcomputer.com/news/security/data-breach-exposes-up-to-142-million-email-logins-at-six-isps/"
source: "BleepingComputer"
severity: "High"
target: "Sistemi email di ISP giapponesi"
cve: null
cvss: null
kev: null
tags: ["news", "cybersecurity"]
news-categories: ["cybersecurity"]
layout: "news"
draft: false
---

Il colosso giapponese delle telecomunicazioni KDDI rivela una violazione del sistema email che coinvolge altri cinque ISP, compromettendo fino a 14,2 milioni di credenziali utente.

{{< cyber-report severity="High" source="BleepingComputer" target="Sistemi email di ISP giapponesi" >}}

L'operatore di telecomunicazioni giapponese KDDI Corporation ha reso nota una violazione dei dati in cui attori malevoli hanno ottenuto l'accesso a uno dei suoi sistemi email utilizzato da altri cinque fornitori di servizi Internet (ISP) nel paese. La violazione potrebbe aver esposto fino a 14,2 milioni di accessi email, colpendo un numero significativo di utenti su più provider.

{{< ad-banner >}}

Il sistema compromesso fa parte dell'infrastruttura email di KDDI, che funge da backend per diversi ISP. Sebbene il metodo esatto di intrusione non sia stato dettagliato, l'incidente sottolinea i rischi insiti nelle architetture di servizio condiviso, dove un singolo punto di guasto può propagarsi a cascata su più organizzazioni.

KDDI ha informato gli ISP interessati e sta lavorando per contenere la violazione. Si consiglia agli utenti di cambiare le password e abilitare l'autenticazione multifattoriale dove disponibile. L'incidente evidenzia la necessità di una solida segmentazione e monitoraggio dei componenti infrastrutturali condivisi.

{{< netrunner-insight >}}

Questa violazione è un esempio da manuale di rischio nella catena di fornitura negli ecosistemi ISP. Gli analisti SOC dovrebbero dare priorità al monitoraggio del movimento laterale dai sistemi email verso altre risorse critiche, mentre i team DevSecOps devono imporre una rigorosa segmentazione di rete e l'accesso con privilegio minimo per i servizi backend condivisi. Nei prossimi settimane ci si aspettano attacchi di credential stuffing mirati a questi account esposti.

{{< /netrunner-insight >}}

---

**[Leggi l'articolo completo su BleepingComputer ›](https://www.bleepingcomputer.com/news/security/data-breach-exposes-up-to-142-million-email-logins-at-six-isps/)**
