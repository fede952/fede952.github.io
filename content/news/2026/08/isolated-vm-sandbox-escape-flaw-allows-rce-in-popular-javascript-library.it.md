---
title: "Difetto di Sandbox Escape in isolated-vm Consente RCE nella Popolare Libreria JavaScript"
date: "2026-08-21T07:37:09Z"
original_date: "2026-08-20T13:48:24"
lang: "it"
translationKey: "isolated-vm-sandbox-escape-flaw-allows-rce-in-popular-javascript-library"
slug: "isolated-vm-sandbox-escape-flaw-allows-rce-in-popular-javascript-library"
author: "NewsBot (Validated by Federico Sella)"
description: "Una falla critica in isolated-vm consente al codice JavaScript in sandbox di sfuggire all'host, permettendo potenziale esecuzione remota di codice. Tutte le versioni fino alla 7.0.0 sono interessate."
original_url: "https://thehackernews.com/2026/08/isolated-vm-flaw-lets-sandboxed.html"
source: "The Hacker News"
severity: "Critical"
target: "libreria sandbox JavaScript isolated-vm"
cve: null
cvss: null
kev: null
tags: ["news", "cybersecurity"]
news-categories: ["cybersecurity"]
layout: "news"
draft: false
---

Una falla critica in isolated-vm consente al codice JavaScript in sandbox di sfuggire all'host, permettendo potenziale esecuzione remota di codice. Tutte le versioni fino alla 7.0.0 sono interessate.

{{< cyber-report severity="Critical" source="The Hacker News" target="libreria sandbox JavaScript isolated-vm" >}}

È stata divulgata una vulnerabilità critica di sicurezza in isolated-vm, una libreria sandbox JavaScript open-source ampiamente utilizzata con oltre 2.900 stelle su GitHub e 190 fork. La falla, tracciata come GHSA-864f-rcv7-6rh4, consente agli attaccanti di sfuggire all'ambiente sandbox e potenzialmente eseguire codice arbitrario sul sistema host. Tutte le versioni della libreria fino alla 7.0.0 inclusa sono interessate.

{{< ad-banner >}}

La vulnerabilità è particolarmente preoccupante perché isolated-vm è progettato per fornire un confine sicuro per l'esecuzione di codice JavaScript non fidato. Una fuga dalla sandbox riuscita potrebbe compromettere l'applicazione host e l'infrastruttura sottostante. Sebbene non sia stato ancora assegnato un identificatore CVE, l'avviso evidenzia la necessità di attenzione immediata da parte degli sviluppatori che utilizzano questa libreria.

Le organizzazioni che si affidano a isolated-vm dovrebbero monitorare le patch e considerare controlli mitiganti, come limitare l'esecuzione di codice non fidato o applicare livelli di isolamento aggiuntivi. La mancanza di un CVE in questo momento non diminuisce la gravità, poiché gli exploit proof-of-concept potrebbero già circolare nella comunità della sicurezza.

{{< netrunner-insight >}}

Questa fuga dalla sandbox è un duro promemoria che anche gli strumenti di isolamento progettati appositamente possono avere difetti critici. Gli analisti SOC dovrebbero inventariare tutte le applicazioni che utilizzano isolated-vm e dare priorità alla patch una volta disponibile una correzione. I team DevSecOps dovrebbero anche rivedere le loro strategie di sandboxing e considerare la difesa in profondità, come eseguire le sandbox in contenitori o VM separati per limitare il raggio d'esplosione.

{{< /netrunner-insight >}}

---

**[Leggi l'articolo completo su The Hacker News ›](https://thehackernews.com/2026/08/isolated-vm-flaw-lets-sandboxed.html)**
