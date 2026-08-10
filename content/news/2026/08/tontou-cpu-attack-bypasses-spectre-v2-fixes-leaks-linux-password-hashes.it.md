---
title: "L'attacco TONTOU alla CPU aggira le correzioni di Spectre v2 e ruba gli hash delle password Linux"
date: "2026-08-10T08:26:15Z"
original_date: "2026-08-06T18:03:45"
lang: "it"
translationKey: "tontou-cpu-attack-bypasses-spectre-v2-fixes-leaks-linux-password-hashes"
slug: "tontou-cpu-attack-bypasses-spectre-v2-fixes-leaks-linux-password-hashes"
author: "NewsBot (Validated by Federico Sella)"
description: "I ricercatori sviluppano l'attacco TONTOU che aggira le recenti mitigazioni di Spectre v2, riuscendo a divulgare segreti inclusi gli hash delle password dai sistemi Linux."
original_url: "https://www.bleepingcomputer.com/news/security/new-tontou-cpu-attack-bypasses-spectre-v2-fixes-leaks-linux-password-hashes/"
source: "BleepingComputer"
severity: "High"
target: "Sistemi Linux"
cve: null
cvss: null
kev: null
tags: ["news", "cybersecurity"]
news-categories: ["cybersecurity"]
layout: "news"
draft: false
---

I ricercatori sviluppano l'attacco TONTOU che aggira le recenti mitigazioni di Spectre v2, riuscendo a divulgare segreti inclusi gli hash delle password dai sistemi Linux.

{{< cyber-report severity="High" source="BleepingComputer" target="Sistemi Linux" >}}

I ricercatori di sicurezza hanno svelato un nuovo attacco di esecuzione speculativa, soprannominato TONTOU, che aggira le recenti mitigazioni per la vulnerabilità Spectre v2. L'attacco prende di mira i meccanismi di predizione dei salti della CPU, che erano stati precedentemente corretti per prevenire perdite tramite canali laterali. Sfruttando una lacuna in queste difese, i ricercatori sono riusciti a estrarre dati sensibili dalla memoria del kernel delle macchine Linux.

{{< ad-banner >}}

La prova di concetto dimostra la gravità del problema riuscendo a rubare gli hash delle password dal sistema target. Ciò indica che l'attacco potrebbe essere utilizzato per compromettere le credenziali degli utenti e potenzialmente elevare i privilegi. I risultati evidenziano la sfida continua nel mitigare completamente gli attacchi a canale laterale dell'esecuzione speculativa, poiché continuano a emergere nuove varianti nonostante le correzioni precedenti.

Sebbene i ricercatori non abbiano ancora rilasciato tutti i dettagli tecnici, il loro lavoro sottolinea la necessità di una vigilanza continua nella sicurezza della CPU. Si consiglia agli amministratori di sistema di monitorare gli aggiornamenti dei fornitori di CPU e delle distribuzioni Linux, e di considerare misure di hardening aggiuntive come la randomizzazione del layout dello spazio degli indirizzi del kernel (KASLR) e gli aggiornamenti del microcodice.

{{< netrunner-insight >}}

Questo attacco è un chiaro promemoria che le vulnerabilità di esecuzione speculativa non sono completamente risolte. Gli analisti SOC dovrebbero dare priorità all'applicazione delle patch e monitorare eventuali indicatori di sfruttamento, mentre gli ingegneri DevSecOps dovrebbero rivedere i loro modelli di minaccia per i rischi di canale laterale. Data la potenziale perdita di hash delle password, è necessaria un'attenzione immediata agli aggiornamenti del kernel Linux e al microcodice della CPU.

{{< /netrunner-insight >}}

---

**[Leggi l'articolo completo su BleepingComputer ›](https://www.bleepingcomputer.com/news/security/new-tontou-cpu-attack-bypasses-spectre-v2-fixes-leaks-linux-password-hashes/)**
