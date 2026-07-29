---
title: "La falla 'Certighost' perseguita i certificati di Microsoft Active Directory"
date: "2026-07-29T09:36:19Z"
original_date: "2026-07-28T16:38:48"
lang: "it"
translationKey: "certighost-flaw-haunts-microsoft-active-directory-certificates"
slug: "certighost-flaw-haunts-microsoft-active-directory-certificates"
author: "NewsBot (Validated by Federico Sella)"
description: "Microsoft ha corretto una vulnerabilità ad alta gravità che consentiva l'escalation dei privilegi negli ambienti Active Directory. Gli analisti SOC dovrebbero dare priorità all'applicazione delle patch."
original_url: "https://www.darkreading.com/vulnerabilities-threats/certighost-flaw-microsoft-active-directory-certificates"
source: "Dark Reading"
severity: "High"
target: "Microsoft Active Directory Certificate Services"
cve: null
cvss: null
kev: null
tags: ["news", "cybersecurity"]
news-categories: ["cybersecurity"]
layout: "news"
draft: false
---

Microsoft ha corretto una vulnerabilità ad alta gravità che consentiva l'escalation dei privilegi negli ambienti Active Directory. Gli analisti SOC dovrebbero dare priorità all'applicazione delle patch.

{{< cyber-report severity="High" source="Dark Reading" target="Microsoft Active Directory Certificate Services" >}}

Microsoft ha corretto una vulnerabilità ad alta gravità in Active Directory Certificate Services, soprannominata 'Certighost', che potrebbe consentire a un attaccante di escalare i privilegi e compromettere un ambiente Active Directory. La falla è stata divulgata da Dark Reading il 28 luglio 2026.

{{< ad-banner >}}

La vulnerabilità interessa il processo di registrazione dei certificati, consentendo a un attore malintenzionato con accesso di basso livello di elevare i propri privilegi a quelli di amministratore di dominio. Ciò potrebbe portare al completo compromesso dell'infrastruttura AD, inclusa la capacità di falsificare certificati e impersonare qualsiasi utente o dispositivo.

Si raccomanda alle organizzazioni che utilizzano Microsoft Active Directory Certificate Services di applicare immediatamente gli ultimi aggiornamenti di sicurezza. La vulnerabilità sottolinea la natura critica dei servizi di certificato nel mantenere la fiducia negli ambienti AD.

{{< netrunner-insight >}}

Questo è un classico vettore d'attacco ai servizi di certificato AD. Assicurati che i tuoi modelli di certificato siano induriti e che le autorizzazioni di registrazione siano strettamente controllate. Applica la patch immediatamente e monitora richieste di certificato insolite o escalation di privilegi.

{{< /netrunner-insight >}}

---

**[Leggi l'articolo completo su Dark Reading ›](https://www.darkreading.com/vulnerabilities-threats/certighost-flaw-microsoft-active-directory-certificates)**
