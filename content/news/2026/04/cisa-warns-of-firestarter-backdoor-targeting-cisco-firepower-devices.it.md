---
title: "CISA avverte del backdoor FIRESTARTER che prende di mira i dispositivi Cisco Firepower"
date: "2026-04-23T12:00:00"
lang: "it"
translationKey: "cisa-warns-of-firestarter-backdoor-targeting-cisco-firepower-devices"
author: "NewsBot (Validated by Federico Sella)"
description: "CISA e NCSC lanciano l'allerta su attori APT che utilizzano il backdoor FIRESTARTER per la persistenza su dispositivi Cisco ASA/FTD. Azioni di risposta urgenti delineate."
original_url: "https://www.cisa.gov/news-events/analysis-reports/ar26-113a"
source: "CISA"
severity: "High"
target: "Dispositivi Cisco Firepower e Secure Firewall"
cve: null
cvss: null
kev: null
tags: ["news", "cybersecurity"]
news-categories: ["cybersecurity"]
layout: "news"
draft: false
---

CISA e NCSC lanciano l'allerta su attori APT che utilizzano il backdoor FIRESTARTER per la persistenza su dispositivi Cisco ASA/FTD. Azioni di risposta urgenti delineate.

{{< cyber-report severity="High" source="CISA" target="Dispositivi Cisco Firepower e Secure Firewall" >}}

CISA e l'NCSC del Regno Unito hanno pubblicato un rapporto di analisi malware sul backdoor FIRESTARTER, utilizzato da attori di minacce persistenti avanzate (APT) per mantenere la persistenza su dispositivi Cisco Firepower e Secure Firewall accessibili pubblicamente che eseguono software ASA o FTD. L'analisi si basa su un campione ottenuto da un'indagine forense e CISA ha confermato impianti riusciti nel mondo reale su dispositivi Cisco Firepower con software ASA.

{{< ad-banner >}}

La pubblicazione è in linea con la Direttiva di Emergenza 25-03 di CISA, che invita le agenzie FCEB statunitensi a raccogliere e inviare dump del core alla piattaforma Malware Next Generation di CISA e a segnalare immediatamente le segnalazioni tramite il Centro Operativo 24/7. Si consiglia alle organizzazioni di non intraprendere ulteriori azioni fino a quando CISA non fornirà i prossimi passi.

Sebbene il malware sia rilevante sia per i dispositivi Cisco Firepower che per i Secure Firewall, CISA ha osservato impianti riusciti solo su dispositivi Firepower che eseguono ASA. Il rapporto sottolinea la necessità di vigilanza e di ricerca proattiva di indicatori di compromissione.

{{< netrunner-insight >}}

Gli analisti SOC dovrebbero dare priorità alla raccolta di dump del core dai dispositivi Cisco ASA/FTD e inviarli a CISA per l'analisi. I team DevSecOps devono garantire che i dispositivi Cisco siano aggiornati e configurati secondo le best practice e monitorare meccanismi di persistenza insoliti. Questo backdoor evidenzia la criticità di proteggere i dispositivi di perimetro di rete contro minacce di livello APT.

{{< /netrunner-insight >}}

---

**[Leggi l'articolo completo su CISA ›](https://www.cisa.gov/news-events/analysis-reports/ar26-113a)**
