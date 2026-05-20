---
title: "CISA avverte di un buffer overflow critico in Siemens RUGGEDCOM APE1808 tramite PAN-OS"
date: "2026-05-20T10:21:56Z"
original_date: "2026-05-19T12:00:00"
lang: "it"
translationKey: "cisa-warns-of-critical-buffer-overflow-in-siemens-ruggedcom-ape1808-via-pan-os"
author: "NewsBot (Validated by Federico Sella)"
description: "Un buffer overflow nel Captive Portal di Palo Alto Networks PAN-OS colpisce i dispositivi Siemens RUGGEDCOM APE1808. CVE-2026-0300 consente l'esecuzione remota di codice non autenticato con privilegi di root."
original_url: "https://www.cisa.gov/news-events/ics-advisories/icsa-26-139-02"
source: "CISA"
severity: "Critical"
target: "Dispositivi Siemens RUGGEDCOM APE1808"
cve: "CVE-2026-0300"
cvss: 10.0
kev: null
tags: ["news", "cybersecurity"]
news-categories: ["cybersecurity"]
layout: "news"
draft: false
---

Un buffer overflow nel Captive Portal di Palo Alto Networks PAN-OS colpisce i dispositivi Siemens RUGGEDCOM APE1808. CVE-2026-0300 consente l'esecuzione remota di codice non autenticato con privilegi di root.

{{< cyber-report severity="Critical" source="CISA" target="Dispositivi Siemens RUGGEDCOM APE1808" cve="CVE-2026-0300" cvss="10.0" >}}

CISA ha pubblicato un avviso (ICSA-26-139-02) che descrive una vulnerabilità critica di buffer overflow nel servizio User-ID Authentication Portal (Captive Portal) del software Palo Alto Networks PAN-OS. Questa falla, tracciata come CVE-2026-0300 con un punteggio CVSS di 10.0, consente a un utente malintenzionato non autenticato di eseguire codice arbitrario con privilegi di root sui firewall delle serie PA e VM inviando pacchetti appositamente predisposti.

{{< ad-banner >}}

La vulnerabilità colpisce i dispositivi Siemens RUGGEDCOM APE1808 in tutte le versioni. Siemens sta preparando versioni di fix e raccomanda di implementare le soluzioni alternative fornite nelle notifiche di sicurezza upstream di Palo Alto Networks. Fino a quando le patch non saranno disponibili, le organizzazioni dovrebbero disabilitare il servizio Captive Portal se non necessario e limitare l'accesso di rete ai dispositivi interessati.

Dato il punteggio CVSS critico e il potenziale di compromissione totale del sistema, è giustificata un'azione immediata. L'avviso è rivolto al settore manifatturiero critico, con dispositivi distribuiti in tutto il mondo. Gli operatori dovrebbero dare priorità all'applicazione delle mitigazioni e monitorare eventuali segni di sfruttamento.

{{< netrunner-insight >}}

Questo è un esempio classico di rischio della supply chain: un componente di terze parti (PAN-OS) introduce una falla critica in un prodotto industriale. Gli analisti SOC dovrebbero immediatamente cercare traffico anomalo verso le porte del Captive Portal e assicurarsi che la segmentazione limiti l'esposizione. I team DevSecOps devono inventariare tutte le istanze di RUGGEDCOM APE1808 e applicare senza indugio le mitigazioni upstream di Palo Alto Networks.

{{< /netrunner-insight >}}

---

**[Leggi l'articolo completo su CISA ›](https://www.cisa.gov/news-events/ics-advisories/icsa-26-139-02)**
