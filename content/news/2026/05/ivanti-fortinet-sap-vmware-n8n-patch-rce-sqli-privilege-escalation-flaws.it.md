---
title: "Ivanti, Fortinet, SAP, VMware, n8n correggono vulnerabilità RCE, SQLi e Privilege Escalation"
date: "2026-05-19T10:36:29Z"
original_date: "2026-05-18T10:54:05"
lang: "it"
translationKey: "ivanti-fortinet-sap-vmware-n8n-patch-rce-sqli-privilege-escalation-flaws"
author: "NewsBot (Validated by Federico Sella)"
description: "Diversi vendor rilasciano fix di sicurezza per vulnerabilità critiche, tra cui Ivanti Xtraction CVE-2026-8043 (CVSS 9.6) che potrebbe portare a divulgazione di informazioni o attacchi lato client."
original_url: "https://thehackernews.com/2026/05/ivanti-fortinet-sap-vmware-n8n-patch.html"
source: "The Hacker News"
severity: "Critical"
target: "Ivanti Xtraction"
cve: "CVE-2026-8043"
cvss: 9.6
kev: null
tags: ["news", "cybersecurity"]
news-categories: ["cybersecurity"]
layout: "news"
draft: false
---

Diversi vendor rilasciano fix di sicurezza per vulnerabilità critiche, tra cui Ivanti Xtraction CVE-2026-8043 (CVSS 9.6) che potrebbe portare a divulgazione di informazioni o attacchi lato client.

{{< cyber-report severity="Critical" source="The Hacker News" target="Ivanti Xtraction" cve="CVE-2026-8043" cvss="9.6" >}}

Ivanti, Fortinet, n8n, SAP e VMware hanno rilasciato patch di sicurezza che risolvono diverse vulnerabilità sfruttabili per bypass dell'autenticazione ed esecuzione arbitraria di codice. La falla più critica è CVE-2026-8043 in Ivanti Xtraction, con un punteggio CVSS di 9.6, che consente il controllo esterno di un nome file, portando a divulgazione di informazioni o attacchi lato client.

{{< ad-banner >}}

Altri vendor hanno anche affrontato problemi di alta gravità, tra cui vulnerabilità di SQL injection e privilege escalation. Le organizzazioni sono invitate a dare priorità alla correzione di queste falle, specialmente quelle esposte a Internet, poiché potrebbero essere concatenate per un compromesso completo del sistema.

Sebbene non sia stata ancora segnalata alcuna attività di sfruttamento, l'ampia superficie d'attacco e gli alti punteggi CVSS richiedono attenzione immediata da parte dei team di sicurezza. La scansione regolare delle vulnerabilità e la gestione delle patch sono fondamentali per mitigare i rischi.

{{< netrunner-insight >}}

Gli analisti SOC dovrebbero dare priorità alla patch per Ivanti Xtraction CVE-2026-8043 a causa del suo punteggio CVSS critico e del potenziale per attacchi lato client. I team DevSecOps devono verificare che tutti i sistemi interessati siano aggiornati e monitorare eventuali segni di sfruttamento, poiché il controllo esterno dei nomi file può portare a esfiltrazione di dati o movimento laterale.

{{< /netrunner-insight >}}

---

**[Leggi l'articolo completo su The Hacker News ›](https://thehackernews.com/2026/05/ivanti-fortinet-sap-vmware-n8n-patch.html)**
