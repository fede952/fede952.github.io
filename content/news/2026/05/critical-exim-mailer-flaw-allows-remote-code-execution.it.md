---
title: "Grave vulnerabilità in Exim consente esecuzione di codice in remoto"
date: "2026-05-14T09:33:22Z"
original_date: "2026-05-13T20:23:50"
lang: "it"
translationKey: "critical-exim-mailer-flaw-allows-remote-code-execution"
author: "NewsBot (Validated by Federico Sella)"
description: "Una vulnerabilità critica nelle configurazioni del mail transfer agent Exim potrebbe consentire a un utente malintenzionato non autenticato di eseguire codice arbitrario in remoto. Applicare immediatamente le patch."
original_url: "https://www.bleepingcomputer.com/news/security/new-critical-exim-mailer-flaw-allows-remote-code-execution/"
source: "BleepingComputer"
severity: "Critical"
target: "Exim mail transfer agent"
cve: null
cvss: null
kev: null
tags: ["news", "cybersecurity"]
news-categories: ["cybersecurity"]
layout: "news"
draft: false
---

Una vulnerabilità critica nelle configurazioni del mail transfer agent Exim potrebbe consentire a un utente malintenzionato non autenticato di eseguire codice arbitrario in remoto. Applicare immediatamente le patch.

{{< cyber-report severity="Critical" source="BleepingComputer" target="Exim mail transfer agent" >}}

È stata scoperta una vulnerabilità critica nel mail transfer agent open-source Exim che interessa determinate configurazioni. La falla potrebbe consentire a un utente malintenzionato remoto non autenticato di eseguire codice arbitrario sui sistemi vulnerabili.

{{< ad-banner >}}

Exim è ampiamente utilizzato come server di posta su sistemi Unix-like, rendendo questa vulnerabilità particolarmente preoccupante per le organizzazioni che si affidano a esso per la consegna delle email. I dettagli tecnici precisi dello sfruttamento non sono stati completamente divulgati, ma il livello di gravità indica che è consigliata l'applicazione immediata delle patch.

Gli amministratori dovrebbero rivedere le loro configurazioni di Exim e applicare tutti gli aggiornamenti disponibili dal progetto Exim. Fino a quando le patch non saranno implementate, si consiglia di adottare controlli di accesso a livello di rete per limitare l'esposizione del servizio vulnerabile.

{{< netrunner-insight >}}

Questo è un vettore critico di esecuzione di codice remoto in un MTA ampiamente distribuito. Gli analisti SOC dovrebbero dare priorità alla scansione delle istanze Exim e verificare l'hardening della configurazione. I team DevSecOps devono accelerare l'applicazione delle patch e considerare regole WAF per bloccare i tentativi di sfruttamento fino all'implementazione degli aggiornamenti.

{{< /netrunner-insight >}}

---

**[Leggi l'articolo completo su BleepingComputer ›](https://www.bleepingcomputer.com/news/security/new-critical-exim-mailer-flaw-allows-remote-code-execution/)**
