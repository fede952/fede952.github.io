---
title: "Patch Tuesday Microsoft Aprile 2026: 167 Vulnerabilità, SharePoint Zero-Day, BlueHammer"
date: "2026-05-11T10:37:48Z"
original_date: "2026-04-14T21:47:59"
lang: "it"
translationKey: "microsoft-patch-tuesday-april-2026-167-flaws-sharepoint-zero-day-bluehammer"
author: "NewsBot (Validated by Federico Sella)"
description: "Microsoft corregge 167 vulnerabilità, inclusi uno zero-day di SharePoint e un difetto di Windows Defender divulgato pubblicamente (BlueHammer). Anche Google Chrome e Adobe Reader correggono bug sfruttati attivamente."
original_url: "https://krebsonsecurity.com/2026/04/patch-tuesday-april-2026-edition/"
source: "Krebs on Security"
severity: "Critical"
target: "Microsoft Windows, SharePoint, Windows Defender, Chrome, Adobe Reader"
cve: null
cvss: null
kev: null
tags: ["news", "cybersecurity"]
news-categories: ["cybersecurity"]
layout: "news"
draft: false
---

Microsoft corregge 167 vulnerabilità, inclusi uno zero-day di SharePoint e un difetto di Windows Defender divulgato pubblicamente (BlueHammer). Anche Google Chrome e Adobe Reader correggono bug sfruttati attivamente.

{{< cyber-report severity="Critical" source="Krebs on Security" target="Microsoft Windows, SharePoint, Windows Defender, Chrome, Adobe Reader" >}}

Il Patch Tuesday di Microsoft di aprile 2026 risolve ben 167 vulnerabilità di sicurezza in Windows e software correlati. Tra le più critiche c'è una vulnerabilità zero-day di SharePoint Server che potrebbe consentire l'esecuzione remota di codice, sebbene nel rapporto non sia stato fornito alcun identificatore CVE. Inoltre, è stata corretta una debolezza divulgata pubblicamente in Windows Defender, soprannominata 'BlueHammer'.

{{< ad-banner >}}

Separatamente, Google Chrome ha corretto il suo quarto zero-day del 2026, continuando una tendenza di frequenti aggiornamenti del browser. Anche Adobe Reader ha ricevuto un aggiornamento urgente per risolvere un difetto sfruttato attivamente che può portare all'esecuzione remota di codice. Le organizzazioni dovrebbero dare priorità a questi aggiornamenti data l'exploitazione attiva.

Il volume enorme di patch di questo mese sottolinea l'importanza di processi di gestione delle patch robusti. I team di sicurezza dovrebbero concentrarsi sullo zero-day di SharePoint e sul problema di Windows Defender come priorità immediate, assicurandosi anche che Chrome e Adobe Reader siano aggiornati in tutta l'azienda.

{{< netrunner-insight >}}

Per gli analisti SOC, dare priorità allo zero-day di SharePoint e al difetto BlueHammer di Windows Defender per l'applicazione immediata delle patch, poiché sono sfruttati attivamente o pubblicamente noti. I team DevSecOps dovrebbero integrare questi aggiornamenti nelle loro pipeline CI/CD e verificare che gli strumenti di protezione degli endpoint non vengano interrotti dalla correzione di Defender. Anche le patch di Chrome e Adobe Reader richiedono attenzione urgente dato il loro stato di sfruttamento attivo.

{{< /netrunner-insight >}}

---

**[Leggi l'articolo completo su Krebs on Security ›](https://krebsonsecurity.com/2026/04/patch-tuesday-april-2026-edition/)**
