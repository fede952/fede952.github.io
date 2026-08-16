---
title: "Affiliato di Akira Ransomware Bypassa l'EDR tramite la Modalità Provvisoria ed Esfiltra Dati"
date: "2026-08-16T07:35:41Z"
original_date: "2026-08-13T20:47:02"
lang: "it"
translationKey: "akira-ransomware-affiliate-bypasses-edr-via-safe-mode-exfiltrates-data"
slug: "akira-ransomware-affiliate-bypasses-edr-via-safe-mode-exfiltrates-data"
author: "NewsBot (Validated by Federico Sella)"
description: "Un affiliato di Akira ransomware disabilita l'EDR avviando in Modalità Provvisoria con Rete, ruba dati ma non riesce a crittografare. Scopri come difenderti."
original_url: "https://www.bleepingcomputer.com/news/security/akira-hackers-disable-edr-with-safe-mode-steal-data-but-fail-to-encrypt/"
source: "BleepingComputer"
severity: "High"
target: "Soluzioni Endpoint Detection and Response (EDR)"
cve: null
cvss: null
kev: null
tags: ["news", "cybersecurity"]
news-categories: ["cybersecurity"]
layout: "news"
draft: false
---

Un affiliato di Akira ransomware disabilita l'EDR avviando in Modalità Provvisoria con Rete, ruba dati ma non riesce a crittografare. Scopri come difenderti.

{{< cyber-report severity="High" source="BleepingComputer" target="Soluzioni Endpoint Detection and Response (EDR)" >}}

È stato osservato un affiliato di Akira ransomware che disabilita le soluzioni Endpoint Detection and Response (EDR) sui sistemi compromessi riavviando la macchina in Modalità Provvisoria con Rete. Questa tecnica consente all'attaccante di operare senza il monitoraggio dell'EDR, poiché molti strumenti di sicurezza non si caricano in Modalità Provvisoria.

{{< ad-banner >}}

L'affiliato è riuscito a esfiltrare dati sensibili dalla rete della vittima, ma la fase di crittografia dell'attacco è fallita. Ciò suggerisce che, sebbene il bypass dell'EDR sia stato efficace, altri controlli di sicurezza o problemi operativi hanno impedito al payload finale del ransomware di eseguirsi correttamente.

Questo incidente evidenzia l'importanza di indurire le configurazioni di avvio e di monitorare riavvii di sistema inattesi, soprattutto in Modalità Provvisoria. Le organizzazioni dovrebbero anche assicurarsi che le soluzioni EDR abbiano la protezione anti-manomissione attivata e che l'avvio in Modalità Provvisoria sia limitato o monitorato.

{{< netrunner-insight >}}

Per gli analisti SOC, questo è un promemoria che i bypass dell'EDR possono essere semplici come un riavvio in Modalità Provvisoria. Monitora eventi di spegnimento/riavvio insoliti e considera di disabilitare l'avvio in Modalità Provvisoria tramite password BIOS/UEFI o criteri di gruppo. I DevSecOps dovrebbero assicurarsi che gli agenti EDR siano configurati per avviarsi in Modalità Provvisoria e che la protezione anti-manomissione sia applicata per prevenire questa comune tecnica di evasione.

{{< /netrunner-insight >}}

---

**[Leggi l'articolo completo su BleepingComputer ›](https://www.bleepingcomputer.com/news/security/akira-hackers-disable-edr-with-safe-mode-steal-data-but-fail-to-encrypt/)**
