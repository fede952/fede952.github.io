---
title: "7-Zip 26.02 corregge una vulnerabilità RCE negli archivi malevoli"
date: "2026-07-19T09:02:18Z"
original_date: "2026-07-18T19:32:02"
lang: "it"
translationKey: "7-zip-26-02-patches-rce-flaw-in-malicious-archives"
slug: "7-zip-26-02-patches-rce-flaw-in-malicious-archives"
author: "NewsBot (Validated by Federico Sella)"
description: "7-Zip ha rilasciato la versione 26.02 per correggere una vulnerabilità di esecuzione remota di codice che può essere attivata aprendo file compressi appositamente creati. Aggiornare immediatamente."
original_url: "https://www.bleepingcomputer.com/news/security/update-now-7-zip-fixes-rce-flaw-exploitable-with-malicious-archives/"
source: "BleepingComputer"
severity: "High"
target: "Utenti di 7-Zip"
cve: null
cvss: null
kev: null
tags: ["news", "cybersecurity"]
news-categories: ["cybersecurity"]
layout: "news"
draft: false
---

7-Zip ha rilasciato la versione 26.02 per correggere una vulnerabilità di esecuzione remota di codice che può essere attivata aprendo file compressi appositamente creati. Aggiornare immediatamente.

{{< cyber-report severity="High" source="BleepingComputer" target="Utenti di 7-Zip" >}}

La versione 26.02 di 7-Zip è stata rilasciata per risolvere una vulnerabilità di esecuzione remota di codice (RCE) che potrebbe consentire agli attaccanti di eseguire codice arbitrario sul sistema della vittima. Il difetto è sfruttabile convincendo gli utenti ad aprire file compressi appositamente creati, come archivi contenenti payload malevoli.

{{< ad-banner >}}

La vulnerabilità riguarda tutte le versioni precedenti del popolare archiviatore di file. Sebbene nell'annuncio non sia stato divulgato alcun identificatore CVE, la gravità è considerata alta a causa del potenziale compromissione totale del sistema. Si consiglia vivamente agli utenti di aggiornare all'ultima versione immediatamente.

Dato l'uso diffuso di 7-Zip sia in ambienti aziendali che consumer, questa patch è critica per ridurre la superficie di attacco. Le organizzazioni dovrebbero dare priorità alla distribuzione tramite meccanismi di aggiornamento automatico o installazione manuale.

{{< netrunner-insight >}}

Gli analisti SOC dovrebbero monitorare attività insolite sui file di archivio e assicurarsi che 7-Zip sia aggiornato su tutti gli endpoint. I team DevSecOps dovrebbero integrare questo aggiornamento nei loro processi di gestione delle patch e considerare di bloccare le versioni precedenti di 7-Zip dall'accesso a sistemi sensibili.

{{< /netrunner-insight >}}

---

**[Leggi l'articolo completo su BleepingComputer ›](https://www.bleepingcomputer.com/news/security/update-now-7-zip-fixes-rce-flaw-exploitable-with-malicious-archives/)**
