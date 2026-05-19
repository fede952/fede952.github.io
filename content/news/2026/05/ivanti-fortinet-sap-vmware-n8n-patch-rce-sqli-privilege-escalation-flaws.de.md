---
title: "Ivanti, Fortinet, SAP, VMware, n8n patchen RCE-, SQLi- und Privilege-Escalation-Sicherheitslücken"
date: "2026-05-19T10:36:29Z"
original_date: "2026-05-18T10:54:05"
lang: "de"
translationKey: "ivanti-fortinet-sap-vmware-n8n-patch-rce-sqli-privilege-escalation-flaws"
author: "NewsBot (Validated by Federico Sella)"
description: "Mehrere Anbieter veröffentlichen Sicherheitsupdates für kritische Schwachstellen, darunter Ivanti Xtraction CVE-2026-8043 (CVSS 9.6), die zu Informationsoffenlegung oder Client-seitigen Angriffen führen können."
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

Mehrere Anbieter veröffentlichen Sicherheitsupdates für kritische Schwachstellen, darunter Ivanti Xtraction CVE-2026-8043 (CVSS 9.6), die zu Informationsoffenlegung oder Client-seitigen Angriffen führen können.

{{< cyber-report severity="Critical" source="The Hacker News" target="Ivanti Xtraction" cve="CVE-2026-8043" cvss="9.6" >}}

Ivanti, Fortinet, n8n, SAP und VMware haben Sicherheitspatches veröffentlicht, die mehrere Schwachstellen beheben, die für Authentifizierungsumgehung und beliebige Codeausführung ausgenutzt werden könnten. Der kritischste Fehler ist CVE-2026-8043 in Ivanti Xtraction mit einem CVSS-Score von 9,6, der eine externe Kontrolle eines Dateinamens ermöglicht, was zu Informationsoffenlegung oder Client-seitigen Angriffen führt.

{{< ad-banner >}}

Andere Anbieter haben ebenfalls schwerwiegende Probleme behoben, darunter SQL-Injection- und Privilege-Escalation-Schwachstellen. Organisationen werden dringend aufgefordert, diese Fehler zu priorisieren, insbesondere bei Systemen, die dem Internet ausgesetzt sind, da sie für eine vollständige Systemkompromittierung verkettet werden könnten.

Obwohl noch keine aktive Ausnutzung gemeldet wurde, erfordern die breite Angriffsfläche und die hohen CVSS-Scores sofortige Aufmerksamkeit der Sicherheitsteams. Regelmäßiges Schwachstellenscanning und Patch-Management sind entscheidend, um Risiken zu mindern.

{{< netrunner-insight >}}

SOC-Analysten sollten den Patch für Ivanti Xtraction CVE-2026-8043 priorisieren, aufgrund seines kritischen CVSS-Scores und des Potenzials für Client-seitige Angriffe. DevSecOps-Teams müssen sicherstellen, dass alle betroffenen Systeme aktualisiert werden und auf Anzeichen einer Ausnutzung achten, da die externe Kontrolle von Dateinamen zu Datenexfiltration oder lateraler Bewegung führen kann.

{{< /netrunner-insight >}}

---

**[Vollständigen Artikel auf The Hacker News lesen ›](https://thehackernews.com/2026/05/ivanti-fortinet-sap-vmware-n8n-patch.html)**
