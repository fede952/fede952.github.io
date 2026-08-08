---
title: "Campagna di phishing AitM prende di mira Microsoft 365 per rubare email finanziarie"
date: "2026-08-08T07:47:42Z"
original_date: "2026-08-07T10:38:27"
lang: "it"
translationKey: "aitm-phishing-campaign-targets-microsoft-365-to-steal-financial-emails"
slug: "aitm-phishing-campaign-targets-microsoft-365-to-steal-financial-emails"
author: "NewsBot (Validated by Federico Sella)"
description: "Una diffusa campagna di phishing via email utilizza l'adversary-in-the-middle per dirottare account Microsoft 365, con l'obiettivo di raccogliere email relative a buste paga e finanze."
original_url: "https://thehackernews.com/2026/08/microsoft-365-aitm-phishing-hijacks.html"
source: "The Hacker News"
severity: "High"
target: "Account Microsoft 365"
cve: null
cvss: null
kev: null
tags: ["news", "cybersecurity"]
news-categories: ["cybersecurity"]
layout: "news"
draft: false
---

Una diffusa campagna di phishing via email utilizza l'adversary-in-the-middle per dirottare account Microsoft 365, con l'obiettivo di raccogliere email relative a buste paga e finanze.

{{< cyber-report severity="High" source="The Hacker News" target="Account Microsoft 365" >}}

I ricercatori di cybersecurity hanno identificato una campagna di phishing attiva e diffusa via email che sfrutta tecniche adversary-in-the-middle (AitM) per compromettere account Microsoft 365. L'obiettivo primario della campagna è identificare il personale chiave coinvolto nei flussi di lavoro finanziari ed esfiltrare le relative comunicazioni email, in particolare quelle riguardanti buste paga e finanze.

{{< ad-banner >}}

Gli attaccanti utilizzano proxy residenziali per mascherare i loro accessi malevoli come normale traffico consumer, eludendo così i controlli di sicurezza che tipicamente segnalano indirizzi IP sospetti. Questa tecnica consente agli attaccanti di mantenere la persistenza e l'accesso agli account compromessi senza sollevare allarmi immediati.

Le organizzazioni che utilizzano Microsoft 365 dovrebbero essere vigili contro tali tentativi di phishing AitM, che spesso bypassano l'autenticazione multi-fattore trasmettendo credenziali e token di sessione in tempo reale. La concentrazione della campagna sui dati finanziari suggerisce uno sforzo mirato a facilitare frodi finanziarie o business email compromise (BEC).

{{< netrunner-insight >}}

Questa campagna sottolinea la necessità di MFA resistente al phishing, come le chiavi di sicurezza FIDO2, e di monitoraggio continuo per accessi anomali, specialmente quelli provenienti da intervalli IP residenziali. I team SOC dovrebbero anche dare priorità alle regole di rilevamento per i toolkit AitM e applicare policy di accesso condizionale che limitino l'accesso in base ai segnali di rischio. Gli ingegneri DevSecOps dovrebbero considerare l'implementazione del binding di sessione e dei controlli di conformità dei dispositivi per mitigare gli attacchi di relay dei token.

{{< /netrunner-insight >}}

---

**[Leggi l'articolo completo su The Hacker News ›](https://thehackernews.com/2026/08/microsoft-365-aitm-phishing-hijacks.html)**
