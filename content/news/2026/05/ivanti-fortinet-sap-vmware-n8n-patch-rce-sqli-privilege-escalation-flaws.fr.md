---
title: "Ivanti, Fortinet, SAP, VMware, n8n corrigent des failles RCE, SQLi et d'escalade de privilèges"
date: "2026-05-19T10:36:29Z"
original_date: "2026-05-18T10:54:05"
lang: "fr"
translationKey: "ivanti-fortinet-sap-vmware-n8n-patch-rce-sqli-privilege-escalation-flaws"
author: "NewsBot (Validated by Federico Sella)"
description: "Plusieurs éditeurs publient des correctifs de sécurité pour des vulnérabilités critiques, notamment Ivanti Xtraction CVE-2026-8043 (CVSS 9.6) pouvant entraîner une divulgation d'informations ou des attaques côté client."
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

Plusieurs éditeurs publient des correctifs de sécurité pour des vulnérabilités critiques, notamment Ivanti Xtraction CVE-2026-8043 (CVSS 9.6) pouvant entraîner une divulgation d'informations ou des attaques côté client.

{{< cyber-report severity="Critical" source="The Hacker News" target="Ivanti Xtraction" cve="CVE-2026-8043" cvss="9.6" >}}

Ivanti, Fortinet, n8n, SAP et VMware ont publié des correctifs de sécurité corrigeant plusieurs vulnérabilités pouvant être exploitées pour un contournement d'authentification et une exécution de code arbitraire. La faille la plus critique est CVE-2026-8043 dans Ivanti Xtraction, avec un score CVSS de 9,6, qui permet un contrôle externe d'un nom de fichier, entraînant une divulgation d'informations ou des attaques côté client.

{{< ad-banner >}}

D'autres éditeurs ont également corrigé des problèmes de haute sévérité, notamment des injections SQL et des vulnérabilités d'escalade de privilèges. Les organisations sont invitées à prioriser le correctif de ces failles, en particulier celles exposées à Internet, car elles pourraient être enchaînées pour compromettre entièrement le système.

Bien qu'aucune exploitation active n'ait encore été signalée, la large surface d'attaque et les scores CVSS élevés justifient une attention immédiate des équipes de sécurité. L'analyse régulière des vulnérabilités et la gestion des correctifs sont essentielles pour atténuer les risques.

{{< netrunner-insight >}}

Les analystes SOC doivent prioriser le correctif Ivanti Xtraction CVE-2026-8043 en raison de son score CVSS critique et du potentiel d'attaques côté client. Les équipes DevSecOps doivent vérifier que tous les systèmes affectés sont mis à jour et surveiller tout signe d'exploitation, car le contrôle externe des noms de fichiers peut entraîner une exfiltration de données ou un mouvement latéral.

{{< /netrunner-insight >}}

---

**[Lire l'article complet sur The Hacker News ›](https://thehackernews.com/2026/05/ivanti-fortinet-sap-vmware-n8n-patch.html)**
