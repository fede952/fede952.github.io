---
title: "Gli attacchi CSS oltrepassano i confini delle email per rubare password e token"
date: "2026-08-09T07:52:16Z"
original_date: "2026-08-08T08:03:57"
lang: "it"
translationKey: "css-attacks-escape-email-boundaries-to-steal-passwords-and-tokens"
slug: "css-attacks-escape-email-boundaries-to-steal-passwords-and-tokens"
author: "NewsBot (Validated by Federico Sella)"
description: "Una nuova ricerca rivela attacchi basati su CSS che escono dal contenuto delle email per dirottare le interfacce di webmail, rubando credenziali e token presso i principali provider."
original_url: "https://thehackernews.com/2026/08/new-css-attacks-can-break-webmail.html"
source: "The Hacker News"
severity: "High"
target: "Interfacce di webmail (Outlook, Gmail, ecc.)"
cve: null
cvss: null
kev: null
tags: ["news", "cybersecurity"]
news-categories: ["cybersecurity"]
layout: "news"
draft: false
---

Una nuova ricerca rivela attacchi basati su CSS che escono dal contenuto delle email per dirottare le interfacce di webmail, rubando credenziali e token presso i principali provider.

{{< cyber-report severity="High" source="The Hacker News" target="Interfacce di webmail (Outlook, Gmail, ecc.)" >}}

Il ricercatore di sicurezza Gareth di PortSwigger ha scoperto una nuova classe di attacchi che sfruttano i CSS per rompere l'isolamento previsto tra il contenuto delle email e l'interfaccia di webmail circostante. Creando email dannose, un attaccante può far sì che il contenuto fuoriesca dal confine del messaggio e interferisca con l'interfaccia utente della webmail stessa, potenzialmente catturando password, rubando token di sessione e dirottando azioni fidate dell'utente.

{{< ad-banner >}}

La ricerca dimostra catene di attacco che colpiscono i principali provider di webmail, tra cui Outlook, Gmail, Fastmail, Proton Mail, Yahoo Mail e AOL Mail. Oltre al furto di credenziali, le tecniche possono essere utilizzate per prendere il controllo di account di terze parti, divulgare token sensibili e persino manipolare strumenti di intelligenza artificiale che leggono le email, ampliando significativamente la superficie di attacco.

Questi risultati evidenziano una debolezza fondamentale nel modo in cui i client di webmail renderizzano contenuti non fidati. Sebbene non sia ancora stato assegnato alcun CVE specifico, l'impatto è grave e le organizzazioni che fanno affidamento sulla webmail dovrebbero monitorare gli aggiornamenti e considerare ulteriori livelli di sicurezza per mitigare potenziali sfruttamenti.

{{< netrunner-insight >}}

Questa ricerca sottolinea che l'email non è solo un vettore per malware, ma può anche essere un'arma contro l'interfaccia stessa di cui gli utenti si fidano. Gli analisti SOC dovrebbero trattare le email sospette come potenziali payload in grado di rompere l'interfaccia utente, non solo come esche di phishing. I team DevSecOps dovrebbero rivedere come i loro client di webmail isolano i contenuti e considerare l'implementazione di rigorose intestazioni Content Security Policy (CSP) per limitare i tentativi di fuga basati su CSS.

{{< /netrunner-insight >}}

---

**[Leggi l'articolo completo su The Hacker News ›](https://thehackernews.com/2026/08/new-css-attacks-can-break-webmail.html)**
