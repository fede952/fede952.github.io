---
title: "Campagna Mini Shai-Hulud compromette i pacchetti npm @antv tramite account del maintainer"
date: "2026-05-19T10:37:35Z"
original_date: "2026-05-19T04:54:17"
lang: "it"
translationKey: "mini-shai-hulud-campaign-compromises-antv-npm-packages-via-maintainer-account"
author: "NewsBot (Validated by Federico Sella)"
description: "Gli attaccanti compromettono l'account del maintainer @antv 'atool' per pubblicare pacchetti npm dannosi, tra cui echarts-for-react con 1,1 milioni di download settimanali, nell'ondata in corso dell'attacco alla supply chain Mini Shai-Hulud."
original_url: "https://thehackernews.com/2026/05/mini-shai-hulud-pushes-malicious-antv.html"
source: "The Hacker News"
severity: "High"
target: "ecosistema npm @antv"
cve: null
cvss: null
kev: null
tags: ["news", "cybersecurity"]
news-categories: ["cybersecurity"]
layout: "news"
draft: false
---

Gli attaccanti compromettono l'account del maintainer @antv 'atool' per pubblicare pacchetti npm dannosi, tra cui echarts-for-react con 1,1 milioni di download settimanali, nell'ondata in corso dell'attacco alla supply chain Mini Shai-Hulud.

{{< cyber-report severity="High" source="The Hacker News" target="ecosistema npm @antv" >}}

I ricercatori di cybersecurity hanno identificato una nuova campagna di attacco alla supply chain software che mira all'ecosistema npm @antv. Gli attaccanti hanno compromesso l'account del maintainer npm 'atool' per pubblicare versioni dannose di diversi pacchetti, tra cui echarts-for-react, un wrapper React ampiamente utilizzato per Apache ECharts con circa 1,1 milioni di download settimanali.

{{< ad-banner >}}

Questa campagna fa parte dell'ondata di attacchi Mini Shai-Hulud in corso, che in precedenza ha preso di mira altri ecosistemi open-source. I pacchetti compromessi probabilmente contengono codice dannoso progettato per esfiltrare dati sensibili o stabilire backdoor negli ambienti di sviluppo.

Le organizzazioni che utilizzano qualsiasi pacchetto @antv dovrebbero immediatamente verificare le proprie dipendenze per individuare segni di compromissione, ruotare le credenziali e rivedere le modifiche recenti nei file di lock. L'intera portata dei pacchetti interessati e il payload esatto sono ancora sotto indagine.

{{< netrunner-insight >}}

Questo attacco sottolinea la necessità critica di misure di sicurezza per la supply chain come la verifica dell'integrità dei pacchetti, l'autenticazione a più fattori per gli account dei maintainer e la scansione automatica delle dipendenze. Gli analisti SOC dovrebbero dare priorità al monitoraggio del traffico anomalo in uscita dalle pipeline di build, mentre i team DevSecOps devono imporre controlli di accesso rigorosi sugli account di pubblicazione dei pacchetti.

{{< /netrunner-insight >}}

---

**[Leggi l'articolo completo su The Hacker News ›](https://thehackernews.com/2026/05/mini-shai-hulud-pushes-malicious-antv.html)**
