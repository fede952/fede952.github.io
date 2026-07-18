---
title: "Sottogruppo GoldenEyeDog Collegato alla Violazione di DigiCert, Furto di Firma del Codice"
date: "2026-07-18T08:46:42Z"
original_date: "2026-07-17T16:39:16"
lang: "it"
translationKey: "goldeneyedog-subgroup-tied-to-digicert-breach-code-signing-theft"
slug: "goldeneyedog-subgroup-tied-to-digicert-breach-code-signing-theft"
author: "NewsBot (Validated by Federico Sella)"
description: "I ricercatori attribuiscono l'incidente di DigiCert dell'aprile 2026 a CylindricalCanine, un sottogruppo del gruppo di cybercriminalità cinese GoldenEyeDog, noto per colpire i settori del gioco d'azzardo e dei videogiochi."
original_url: "https://thehackernews.com/2026/07/goldeneyedog-subgroup-linked-to.html"
source: "The Hacker News"
severity: "High"
target: "Infrastruttura di firma del codice di DigiCert"
cve: null
cvss: null
kev: null
tags: ["news", "cybersecurity"]
news-categories: ["cybersecurity"]
layout: "news"
draft: false
---

I ricercatori attribuiscono l'incidente di DigiCert dell'aprile 2026 a CylindricalCanine, un sottogruppo del gruppo di cybercriminalità cinese GoldenEyeDog, noto per colpire i settori del gioco d'azzardo e dei videogiochi.

{{< cyber-report severity="High" source="The Hacker News" target="Infrastruttura di firma del codice di DigiCert" >}}

I ricercatori di cybersecurity hanno attribuito l'incidente di sicurezza dell'aprile 2026 presso DigiCert a un cluster di attività di minaccia denominato CylindricalCanine. Il gruppo è descritto come un sottogruppo di GoldenEyeDog (noto anche come APT-Q-27, Dragon Breath e Miuuti Group), un gruppo di cybercriminalità cinese che storicamente prende di mira i settori del gioco d'azzardo e dei videogiochi.

{{< ad-banner >}}

La violazione ha comportato il furto di certificati di firma del codice, che potrebbe consentire agli attori delle minacce di firmare software dannoso con credenziali legittime, bypassando i controlli di sicurezza. Expel ha condiviso dettagli tecnici dell'evento, evidenziando la natura sofisticata dell'operazione.

Le organizzazioni che si affidano ai certificati emessi da DigiCert dovrebbero rivedere i propri inventari di certificati e monitorare eventuali usi non autorizzati. L'incidente sottolinea i rischi posti dagli attacchi alla supply chain che prendono di mira autorità di certificazione fidate.

{{< netrunner-insight >}}

Per gli analisti SOC: dare priorità al monitoraggio di anomalie nella firma del codice e utilizzi imprevisti di certificati. I team DevSecOps dovrebbero imporre una gestione rigorosa del ciclo di vita dei certificati e considerare certificati a vita breve per limitare l'esposizione in caso di furto.

{{< /netrunner-insight >}}

---

**[Leggi l'articolo completo su The Hacker News ›](https://thehackernews.com/2026/07/goldeneyedog-subgroup-linked-to.html)**
