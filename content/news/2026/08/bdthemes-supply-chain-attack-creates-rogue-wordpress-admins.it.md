---
title: "Attacco alla supply chain di BdThemes crea admin WordPress non autorizzati"
date: "2026-08-11T08:10:19Z"
original_date: "2026-08-11T05:48:44"
lang: "it"
translationKey: "bdthemes-supply-chain-attack-creates-rogue-wordpress-admins"
slug: "bdthemes-supply-chain-attack-creates-rogue-wordpress-admins"
author: "NewsBot (Validated by Federico Sella)"
description: "Il compromesso della supply chain colpisce i plugin WordPress di BdThemes; nessuna modifica al codice sorgente, ma JSON malevolo crea account admin non autorizzati."
original_url: "https://thehackernews.com/2026/08/bdthemes-supply-chain-attack-poisons.html"
source: "The Hacker News"
severity: "High"
target: "Siti WordPress che utilizzano plugin BdThemes"
cve: null
cvss: null
kev: null
tags: ["news", "cybersecurity"]
news-categories: ["cybersecurity"]
layout: "news"
draft: false
---

Il compromesso della supply chain colpisce i plugin WordPress di BdThemes; nessuna modifica al codice sorgente, ma JSON malevolo crea account admin non autorizzati.

{{< cyber-report severity="High" source="The Hacker News" target="Siti WordPress che utilizzano plugin BdThemes" >}}

I ricercatori di cybersecurity hanno divulgato un attacco alla supply chain che ha preso di mira BdThemes, un fornitore di plugin WordPress. Il compromesso ha portato alla disattivazione temporanea dei download dei plugin da parte del team dei plugin WordPress. In particolare, l'attacco si discosta dai tipici incidenti della supply chain: nessun file di codice sorgente all'interno del repository ufficiale WordPress.org è stato modificato.

{{< ad-banner >}}

Invece, l'attacco sfrutta payload JSON malevoli per creare account amministratore WordPress non autorizzati. Questa tecnica consente agli aggressori di ottenere accesso non autorizzato ai siti colpiti senza alterare i file principali del plugin, rendendo il rilevamento più difficile per i controlli standard di integrità.

Il ricercatore di Wordfence Paolo Tresso ha evidenziato la natura insolita dell'attacco, sottolineando che l'assenza di modifiche al codice sorgente evidenzia la necessità di un monitoraggio completo della supply chain che vada oltre la sola integrità del codice.

{{< netrunner-insight >}}

Questo attacco sottolinea l'importanza di monitorare non solo le modifiche al codice ma anche i file di configurazione e dati come JSON. Per gli analisti SOC, trattare gli aggiornamenti dei plugin come eventi ad alto rischio e verificare l'integrità di tutti i file, non solo del codice sorgente. DevSecOps dovrebbe implementare il monitoraggio in tempo reale per la creazione inaspettata di account amministratore e considerare il monitoraggio dell'integrità dei file che copra anche le risorse non di codice.

{{< /netrunner-insight >}}

---

**[Leggi l'articolo completo su The Hacker News ›](https://thehackernews.com/2026/08/bdthemes-supply-chain-attack-poisons.html)**
