---
title: "PoC di bypass zero-day di Windows BitLocker rilasciato: YellowKey e GreenPlasma"
date: "2026-05-14T09:30:15Z"
original_date: "2026-05-13T16:37:49"
lang: "it"
translationKey: "windows-bitlocker-zero-day-bypass-poc-released-yellowkey-and-greenplasma"
author: "NewsBot (Validated by Federico Sella)"
description: "Sono stati pubblicati proof-of-concept per due vulnerabilità Windows non patchate—YellowKey (bypass di BitLocker) e GreenPlasma (elevazione dei privilegi)—che rappresentano un rischio per i drive crittografati."
original_url: "https://www.bleepingcomputer.com/news/security/windows-bitlocker-zero-day-gives-access-to-protected-drives-poc-released/"
source: "BleepingComputer"
severity: "High"
target: "Drive protetti da Windows BitLocker"
cve: null
cvss: null
kev: null
tags: ["news", "cybersecurity"]
news-categories: ["cybersecurity"]
layout: "news"
draft: false
---

Sono stati pubblicati proof-of-concept per due vulnerabilità Windows non patchate—YellowKey (bypass di BitLocker) e GreenPlasma (elevazione dei privilegi)—che rappresentano un rischio per i drive crittografati.

{{< cyber-report severity="High" source="BleepingComputer" target="Drive protetti da Windows BitLocker" >}}

Un ricercatore di cybersecurity ha rilasciato proof-of-concept (PoC) per due vulnerabilità Microsoft Windows non patchate, denominate YellowKey e GreenPlasma. YellowKey è un bypass di BitLocker che consente agli attaccanti di accedere ai dati su drive protetti senza autenticazione adeguata, mentre GreenPlasma è un difetto di elevazione dei privilegi che potrebbe permettere a un attaccante di ottenere permessi elevati su un sistema compromesso.

{{< ad-banner >}}

La pubblicazione di questi PoC aumenta il rischio di sfruttamento, poiché gli attori delle minacce possono ora armare le tecniche. Le organizzazioni che si affidano a BitLocker per la crittografia completa del disco dovrebbero valutare la propria esposizione e considerare controlli di sicurezza aggiuntivi, come l'abilitazione della protezione TPM+PIN o l'uso dell'autenticazione pre-avvio.

Microsoft non ha ancora rilasciato patch per queste vulnerabilità, lasciando i sistemi esposti fino al rilascio delle correzioni. I team di sicurezza dovrebbero monitorare modelli di accesso insoliti ai drive crittografati e applicare soluzioni alternative dove possibile, come disabilitare opzioni di avvio non necessarie o imporre politiche PIN forti.

{{< netrunner-insight >}}

Per gli analisti SOC, dare priorità al monitoraggio di tentativi non autorizzati di accesso ai drive protetti da BitLocker e agli eventi di elevazione dei privilegi. Gli ingegneri DevSecOps dovrebbero testare i propri ambienti contro i PoC pubblicati per identificare configurazioni vulnerabili e implementare controlli compensativi come Secure Boot e log di avvio misurati.

{{< /netrunner-insight >}}

---

**[Leggi l'articolo completo su BleepingComputer ›](https://www.bleepingcomputer.com/news/security/windows-bitlocker-zero-day-gives-access-to-protected-drives-poc-released/)**
