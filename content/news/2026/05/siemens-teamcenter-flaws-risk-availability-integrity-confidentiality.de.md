---
title: "Siemens Teamcenter-Schwachstellen gefährden Verfügbarkeit, Integrität und Vertraulichkeit"
date: "2026-05-16T08:47:33Z"
original_date: "2026-05-14T12:00:00"
lang: "de"
translationKey: "siemens-teamcenter-flaws-risk-availability-integrity-confidentiality"
author: "NewsBot (Validated by Federico Sella)"
description: "Mehrere Schwachstellen in Siemens Teamcenter könnten Verfügbarkeit, Integrität und Vertraulichkeit beeinträchtigen. Aktualisieren Sie umgehend auf die neuesten Versionen."
original_url: "https://www.cisa.gov/news-events/ics-advisories/icsa-26-134-04"
source: "CISA"
severity: "High"
target: "Siemens Teamcenter"
cve: "CVE-2024-4367"
cvss: 7.5
kev: null
tags: ["news", "cybersecurity"]
news-categories: ["cybersecurity"]
layout: "news"
draft: false
---

Mehrere Schwachstellen in Siemens Teamcenter könnten Verfügbarkeit, Integrität und Vertraulichkeit beeinträchtigen. Aktualisieren Sie umgehend auf die neuesten Versionen.

{{< cyber-report severity="High" source="CISA" target="Siemens Teamcenter" cve="CVE-2024-4367" cvss="7.5" >}}

Siemens Teamcenter ist von mehreren Schwachstellen betroffen, die zu einer Beeinträchtigung von Verfügbarkeit, Integrität und Vertraulichkeit führen können. Zu den Fehlern gehören eine unzureichende Prüfung auf ungewöhnliche oder außergewöhnliche Bedingungen, Cross-Site-Scripting und die Verwendung hartcodierter Anmeldeinformationen. Betroffene Versionen umfassen Teamcenter V2312, V2406, V2412, V2506 und V2512.

{{< ad-banner >}}

Bei CVE-2024-4367 fehlt eine Typprüfung bei der Verarbeitung von Schriftarten in PDF.js, was die Ausführung beliebigen JavaScript-Codes im PDF.js-Kontext ermöglicht. Diese Schwachstelle betrifft Firefox und Thunderbird, ist jedoch im Siemens Advisory aufgeführt. Siemens empfiehlt, auf die neuesten Versionen von Teamcenter zu aktualisieren, um diese Risiken zu mindern.

Die Schwachstellen haben einen CVSS v3-Basiswert von 7,5, was auf eine hohe Schwere hindeutet. Kritische Fertigungssektoren sind betroffen, mit weltweitem Einsatz. Organisationen sollten das Patchen priorisieren und ihre Gefährdung durch diese Schwachstellen überprüfen.

{{< netrunner-insight >}}

SOC-Analysten sollten sofort alle Teamcenter-Instanzen inventarisieren und das Patchen auf die neuesten Versionen priorisieren. DevSecOps-Teams müssen sicherstellen, dass PDF.js-Komponenten aktualisiert werden und auf Ausnutzungsversuche dieser CVEs achten. Angesichts des hohen CVSS-Scores und des Potenzials für eine vollständige Kompromittierung behandeln Sie dies als eine Remediation mit hoher Priorität.

{{< /netrunner-insight >}}

---

**[Vollständigen Artikel auf CISA lesen ›](https://www.cisa.gov/news-events/ics-advisories/icsa-26-134-04)**
