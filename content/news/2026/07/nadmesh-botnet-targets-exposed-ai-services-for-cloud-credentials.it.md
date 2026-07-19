---
title: "Botnet NadMesh prende di mira servizi AI esposti per rubare credenziali cloud"
date: "2026-07-19T09:05:56Z"
original_date: "2026-07-17T17:12:23"
lang: "it"
translationKey: "nadmesh-botnet-targets-exposed-ai-services-for-cloud-credentials"
slug: "nadmesh-botnet-targets-exposed-ai-services-for-cloud-credentials"
author: "NewsBot (Validated by Federico Sella)"
description: "Un nuovo botnet basato su Go, NadMesh, caccia piattaforme AI esposte come ComfyUI e Ollama, rubando chiavi AWS e token Kubernetes. Oltre 3.800 chiavi dichiarate rubate."
original_url: "https://thehackernews.com/2026/07/new-nadmesh-botnet-hunts-exposed-ai.html"
source: "The Hacker News"
severity: "High"
target: "Servizi AI esposti (ComfyUI, Ollama, n8n, ecc.)"
cve: null
cvss: null
kev: null
tags: ["news", "cybersecurity"]
news-categories: ["cybersecurity"]
layout: "news"
draft: false
---

Un nuovo botnet basato su Go, NadMesh, caccia piattaforme AI esposte come ComfyUI e Ollama, rubando chiavi AWS e token Kubernetes. Oltre 3.800 chiavi dichiarate rubate.

{{< cyber-report severity="High" source="The Hacker News" target="Servizi AI esposti (ComfyUI, Ollama, n8n, ecc.)" >}}

Un nuovo botnet chiamato NadMesh, scritto in Go, è emerso all'inizio di luglio 2026, prendendo di mira servizi AI esposti per rubare credenziali cloud e token Kubernetes. La dashboard operativa del botnet mostra apparentemente 3.811 chiavi AWS uniche raccolte, indicando una scala operativa significativa. NadMesh utilizza un raccoglitore basato su Shodan per popolare continuamente la sua coda di scansione con istanze vulnerabili di strumenti AI popolari come ComfyUI, Ollama, n8n, Open WebUI, Langflow e Gradio.

{{< ad-banner >}}

Queste piattaforme AI sono spesso distribuite rapidamente dai team di sviluppo senza un adeguato hardening di sicurezza, lasciandole esposte a Internet. Il botnet sfrutta questa mancanza di protezione firewall per ottenere accesso ed estrarre credenziali sensibili. L'attenzione sui servizi AI suggerisce un cambiamento nel targeting degli attaccanti verso infrastrutture cloud ad alto valore e pipeline di machine learning.

Le organizzazioni che eseguono questi strumenti AI dovrebbero immediatamente verificare la loro esposizione, limitare l'accesso di rete e ruotare tutte le credenziali che potrebbero essere state compromesse. Il botnet NadMesh dimostra il crescente panorama delle minacce in cui i servizi AI malconfigurati diventano obiettivi primari per il furto di credenziali e il movimento laterale.

{{< netrunner-insight >}}

Per gli analisti SOC: dare priorità alla scansione per servizi AI esposti come ComfyUI, Ollama e simili nel proprio ambiente. I team DevSecOps devono imporre la segmentazione di rete e le regole firewall prima di distribuire questi strumenti. Il botnet NadMesh è un chiaro promemoria che la distribuzione rapida senza revisione della sicurezza invita alla raccolta automatizzata di credenziali.

{{< /netrunner-insight >}}

---

**[Leggi l'articolo completo su The Hacker News ›](https://thehackernews.com/2026/07/new-nadmesh-botnet-hunts-exposed-ai.html)**
