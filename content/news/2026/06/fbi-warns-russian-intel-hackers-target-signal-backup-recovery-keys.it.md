---
title: "FBI avverte: hacker dell'intelligence russa prendono di mira le chiavi di ripristino del backup di Signal"
date: "2026-06-28T09:57:31Z"
original_date: "2026-06-26T19:38:29"
lang: "it"
translationKey: "fbi-warns-russian-intel-hackers-target-signal-backup-recovery-keys"
author: "NewsBot (Validated by Federico Sella)"
description: "FBI e CISA aggiornano l'avviso: il phishing dell'intelligence russa ora ruba le chiavi di ripristino del backup di Signal per leggere messaggi privati e prendere il controllo degli account."
original_url: "https://thehackernews.com/2026/06/fbi-warns-russian-intelligence-hackers.html"
source: "The Hacker News"
severity: "High"
target: "utenti di Signal"
cve: null
cvss: null
kev: null
tags: ["news", "cybersecurity"]
news-categories: ["cybersecurity"]
layout: "news"
draft: false
---

FBI e CISA aggiornano l'avviso: il phishing dell'intelligence russa ora ruba le chiavi di ripristino del backup di Signal per leggere messaggi privati e prendere il controllo degli account.

{{< cyber-report severity="High" source="The Hacker News" target="utenti di Signal" >}}

FBI e CISA hanno aggiornato il loro avviso di marzo sulle campagne di phishing dell'intelligence russa mirate agli account Signal. Gli aggressori hanno aggiunto un nuovo passaggio: ora inducono le vittime a consegnare la loro chiave di ripristino del backup di Signal. Una volta ottenuta, la chiave consente all'aggressore di ripristinare il backup dell'account, leggere la cronologia dei messaggi privati e di gruppo e prendere il controllo completo dell'account.

{{< ad-banner >}}

La chiave rimane valida anche dopo il compromesso iniziale, consentendo un accesso persistente. Questa tecnica bypassa l'autenticazione a due fattori tradizionale perché la chiave di ripristino è progettata per il ripristino legittimo dell'account. L'avviso sottolinea che gli utenti non dovrebbero mai condividere la propria chiave di ripristino e dovrebbero attivare il blocco della registrazione e altre funzionalità di sicurezza.

Le organizzazioni dovrebbero informare gli utenti su questo specifico vettore di phishing e considerare l'implementazione di passaggi di verifica aggiuntivi per le comunicazioni sensibili. La minaccia è attribuita ad attori dell'intelligence russa, evidenziando il contesto geopolitico della campagna.

{{< netrunner-insight >}}

Questo è un esempio da manuale di ingegneria sociale che prende di mira una funzionalità di sicurezza. Gli analisti SOC dovrebbero monitorare richieste insolite di ripristino account e informare gli utenti che la chiave di ripristino del backup di Signal non deve mai essere condivisa. I team DevSecOps dovrebbero considerare l'integrazione di un'autenticazione resistente al phishing per le comunicazioni critiche.

{{< /netrunner-insight >}}

---

**[Leggi l'articolo completo su The Hacker News ›](https://thehackernews.com/2026/06/fbi-warns-russian-intelligence-hackers.html)**
