---
title: "CISA mette in guardia da una falla in Rockwell RSLinx Classic che porta a DoS"
date: "2026-06-17T11:42:55Z"
original_date: "2026-06-16T12:00:00"
lang: "it"
translationKey: "cisa-warns-of-rockwell-rslinx-classic-flaw-leading-to-dos"
author: "NewsBot (Validated by Federico Sella)"
description: "L'avviso CISA evidenzia CVE-2020-13573, un buffer overflow basato su stack in Rockwell Automation RSLinx Classic ≤4.50.00, che rischia denial of service e esecuzione remota di codice."
original_url: "https://www.cisa.gov/news-events/ics-advisories/icsa-26-167-02"
source: "CISA"
severity: "High"
target: "Rockwell Automation RSLinx Classic"
cve: "CVE-2020-13573"
cvss: 7.5
kev: null
tags: ["news", "cybersecurity"]
news-categories: ["cybersecurity"]
layout: "news"
draft: false
---

L'avviso CISA evidenzia CVE-2020-13573, un buffer overflow basato su stack in Rockwell Automation RSLinx Classic ≤4.50.00, che rischia denial of service e esecuzione remota di codice.

{{< cyber-report severity="High" source="CISA" target="Rockwell Automation RSLinx Classic" cve="CVE-2020-13573" cvss="7.5" >}}

CISA ha pubblicato un avviso (ICSA-26-167-02) riguardante una vulnerabilità in Rockwell Automation RSLinx Classic, un software di comunicazione industriale ampiamente utilizzato. La falla, identificata come CVE-2020-13573, è un buffer overflow basato su stack che può essere sfruttato da remoto per eseguire codice arbitrario o causare un denial of service, rendendo l'applicazione non reattiva e incapace di riprendersi automaticamente.

{{< ad-banner >}}

Le versioni interessate includono RSLinx Classic fino alla versione 4.50.00 inclusa. La vulnerabilità ha un punteggio CVSS v3 di 7.5, indicando alta gravità. Rockwell Automation raccomanda di aggiornare alla versione 4.60.00 o successiva, o di applicare la patch BF31213 per i clienti che non possono aggiornare immediatamente. L'avviso fa anche riferimento a CWE-125 (Lettura fuori dai limiti) come debolezza sottostante.

Considerando i settori delle infrastrutture critiche coinvolti—Manifatturiero critico, Energia, Alimentare e Agricolo, e Acqua e Acque reflue—e la distribuzione globale del prodotto, l'applicazione tempestiva delle patch è essenziale. Le organizzazioni dovrebbero dare priorità a questo aggiornamento per mitigare il rischio di sfruttamento, specialmente in ambienti in cui RSLinx Classic è esposto a reti non fidate.

{{< netrunner-insight >}}

Per gli analisti SOC, monitorare crash insoliti o mancata risposta nei processi RSLinx Classic, poiché potrebbero indicare tentativi di sfruttamento. I team DevSecOps dovrebbero pianificare immediatamente l'aggiornamento alla versione 4.60.00 o applicare la patch BF31213, e assicurarsi che le istanze RSLinx non siano direttamente accessibili da Internet. Dato il punteggio CVSS e il potenziale di esecuzione remota di codice, trattare questo come un elemento di remediation ad alta priorità.

{{< /netrunner-insight >}}

---

**[Leggi l'articolo completo su CISA ›](https://www.cisa.gov/news-events/ics-advisories/icsa-26-167-02)**
