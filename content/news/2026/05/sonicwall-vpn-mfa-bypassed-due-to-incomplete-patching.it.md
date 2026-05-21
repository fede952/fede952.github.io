---
title: "Bypass MFA su SonicWall VPN a causa di patch incomplete"
date: "2026-05-21T10:35:14Z"
original_date: "2026-05-20T21:19:17"
lang: "it"
translationKey: "sonicwall-vpn-mfa-bypassed-due-to-incomplete-patching"
author: "NewsBot (Validated by Federico Sella)"
description: "Attori malevoli forzano le credenziali VPN e bypassano l'MFA su appliance SonicWall Gen6 SSL-VPN non aggiornate, distribuendo strumenti ransomware."
original_url: "https://www.bleepingcomputer.com/news/security/hackers-bypass-sonicwall-vpn-mfa-due-to-incomplete-patching/"
source: "BleepingComputer"
severity: "High"
target: "Appliance SonicWall Gen6 SSL-VPN"
cve: null
cvss: null
kev: null
tags: ["news", "cybersecurity"]
news-categories: ["cybersecurity"]
layout: "news"
draft: false
---

Attori malevoli forzano le credenziali VPN e bypassano l'MFA su appliance SonicWall Gen6 SSL-VPN non aggiornate, distribuendo strumenti ransomware.

{{< cyber-report severity="High" source="BleepingComputer" target="Appliance SonicWall Gen6 SSL-VPN" >}}

È stato osservato che attori malevoli forzano le credenziali VPN e bypassano l'autenticazione multi-fattore (MFA) su appliance SonicWall Gen6 SSL-VPN. Gli attacchi sfruttano patch incomplete, consentendo agli avversari di distribuire strumenti comunemente usati in operazioni ransomware.

{{< ad-banner >}}

La vulnerabilità consente agli attaccanti di ottenere accesso non autorizzato alle reti interne dopo aver compromesso le credenziali VPN. Una volta dentro, possono muoversi lateralmente e distribuire payload ransomware, rappresentando un rischio significativo per le organizzazioni che si affidano a questi appliance per l'accesso remoto.

SonicWall ha rilasciato patch per risolvere il problema, ma l'applicazione incompleta di questi aggiornamenti lascia i sistemi esposti. Le organizzazioni sono invitate a verificare che tutte le patch raccomandate siano completamente installate e a monitorare eventuali segni di accesso VPN non autorizzato.

{{< netrunner-insight >}}

Questo incidente sottolinea l'importanza critica di una gestione approfondita delle patch. Gli analisti SOC dovrebbero dare priorità alla verifica che tutti gli appliance SonicWall Gen6 abbiano il firmware più recente e monitorare i log VPN per pattern di autenticazione anomali. I team DevSecOps dovrebbero considerare l'implementazione di ulteriori livelli MFA e segmentazione di rete per mitigare tali bypass.

{{< /netrunner-insight >}}

---

**[Leggi l'articolo completo su BleepingComputer ›](https://www.bleepingcomputer.com/news/security/hackers-bypass-sonicwall-vpn-mfa-due-to-incomplete-patching/)**
