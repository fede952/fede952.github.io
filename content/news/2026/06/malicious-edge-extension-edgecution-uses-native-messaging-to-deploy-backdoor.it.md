---
title: "Estensione Edge dannosa 'Edgecution' usa Native Messaging per distribuire backdoor"
date: "2026-06-25T10:16:09Z"
original_date: "2026-06-24T20:58:22"
lang: "it"
translationKey: "malicious-edge-extension-edgecution-uses-native-messaging-to-deploy-backdoor"
author: "NewsBot (Validated by Federico Sella)"
description: "Un'estensione dannosa di Microsoft Edge chiamata 'Edgecution' evade la sandbox del browser tramite Native Messaging per distribuire un backdoor basato su Python in attacchi ransomware."
original_url: "https://www.bleepingcomputer.com/news/security/malicious-edge-extension-abuses-native-messaging-as-bridge-to-malware/"
source: "BleepingComputer"
severity: "High"
target: "Utenti di Microsoft Edge"
cve: null
cvss: null
kev: null
tags: ["news", "cybersecurity"]
news-categories: ["cybersecurity"]
layout: "news"
draft: false
---

Un'estensione dannosa di Microsoft Edge chiamata 'Edgecution' evade la sandbox del browser tramite Native Messaging per distribuire un backdoor basato su Python in attacchi ransomware.

{{< cyber-report severity="High" source="BleepingComputer" target="Utenti di Microsoft Edge" >}}

Un'estensione dannosa di Microsoft Edge soprannominata 'Edgecution' è stata osservata in un attacco ransomware, sfruttando l'API Native Messaging del browser per evadere la sandbox ed eseguire codice arbitrario sul sistema host. L'estensione funge da ponte per distribuire un backdoor basato su Python, consentendo accesso persistente e ulteriori attività dannose.

{{< ad-banner >}}

La catena d'attacco inizia con l'installazione dell'estensione dannosa, che poi abusa di Native Messaging per comunicare con un'applicazione nativa al di fuori della sandbox del browser. Questa tecnica bypassa i tipici confini di sicurezza del browser, permettendo all'attaccante di eseguire comandi e rilasciare payload aggiuntivi, incluso il ransomware.

I ricercatori di sicurezza sottolineano che questo metodo è particolarmente insidioso perché sfrutta una funzionalità legittima del browser, rendendo il rilevamento difficile per le soluzioni di sicurezza endpoint tradizionali. Si consiglia alle organizzazioni di monitorare le estensioni del browser non autorizzate e limitare le autorizzazioni di Native Messaging dove possibile.

{{< netrunner-insight >}}

Questo attacco sottolinea l'importanza di monitorare le installazioni di estensioni del browser e l'attività di Native Messaging. Gli analisti SOC dovrebbero cercare comportamenti anomali delle estensioni e comunicazioni inaspettate con host nativi, mentre i team DevSecOps dovrebbero applicare liste di autorizzazione rigorose per le estensioni e disabilitare gli host Native Messaging non necessari.

{{< /netrunner-insight >}}

---

**[Leggi l'articolo completo su BleepingComputer ›](https://www.bleepingcomputer.com/news/security/malicious-edge-extension-abuses-native-messaging-as-bridge-to-malware/)**
