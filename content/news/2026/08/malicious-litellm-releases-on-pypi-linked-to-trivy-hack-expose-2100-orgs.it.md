---
title: "Rilasci Maligni di LiteLLM su PyPI Collegati all'Hack di Trivy Espongono Oltre 2.100 Organizzazioni"
date: "2026-08-17T07:48:06Z"
original_date: "2026-08-12T08:04:52"
lang: "it"
translationKey: "malicious-litellm-releases-on-pypi-linked-to-trivy-hack-expose-2100-orgs"
slug: "malicious-litellm-releases-on-pypi-linked-to-trivy-hack-expose-2100-orgs"
author: "NewsBot (Validated by Federico Sella)"
description: "Due pacchetti LiteLLM maligni su PyPI hanno rubato chiavi cloud, chiavi SSH e altro. I dati di CloudSEK suggeriscono che oltre 2.100 organizzazioni potrebbero essere esposte."
original_url: "https://thehackernews.com/2026/08/malicious-litellm-releases-tied-to.html"
source: "The Hacker News"
severity: "High"
target: "Utenti di LiteLLM su PyPI"
cve: null
cvss: null
kev: null
tags: ["news", "cybersecurity"]
news-categories: ["cybersecurity"]
layout: "news"
draft: false
---

Due pacchetti LiteLLM maligni su PyPI hanno rubato chiavi cloud, chiavi SSH e altro. I dati di CloudSEK suggeriscono che oltre 2.100 organizzazioni potrebbero essere esposte.

{{< cyber-report severity="High" source="The Hacker News" target="Utenti di LiteLLM su PyPI" >}}

Due rilasci maligni di LiteLLM sono stati pubblicati su PyPI e sono rimasti disponibili per circa 40 minuti a marzo. Questi pacchetti contenevano codice per il furto di credenziali progettato per raccogliere un'ampia gamma di segreti, inclusi chiavi di accesso cloud, chiavi private SSH, token Kubernetes e password di database da qualsiasi sistema che li avesse installati.

{{< ad-banner >}}

L'azienda di intelligence sulle minacce CloudSEK ha ottenuto un dataset costruito da circa 434.000 file che gli attaccanti hanno catturato. L'analisi di questo dataset suggerisce che l'esposizione potrebbe riguardare più di 2.100 organizzazioni, evidenziando la potenziale portata del compromesso.

L'incidente è collegato al precedente hack di Trivy, indicando un attacco coordinato alla supply chain. Le organizzazioni che hanno installato LiteLLM da PyPI durante la finestra interessata dovrebbero immediatamente ruotare tutte le credenziali esposte e indagare per segni di accesso non autorizzato.

{{< netrunner-insight >}}

Questo incidente sottolinea la necessità critica di vigilanza sulla supply chain del software. Gli analisti SOC dovrebbero monitorare eventuali installazioni delle versioni dannose di LiteLLM e dare priorità alla rotazione delle credenziali per qualsiasi segreto potenzialmente esposto. I team DevSecOps dovrebbero imporre controlli rigorosi sull'integrità dei pacchetti e considerare l'uso di mirror privati o file di blocco con hash per mitigare tali rischi.

{{< /netrunner-insight >}}

---

**[Leggi l'articolo completo su The Hacker News ›](https://thehackernews.com/2026/08/malicious-litellm-releases-tied-to.html)**
