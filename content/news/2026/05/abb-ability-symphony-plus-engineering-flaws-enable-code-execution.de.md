---
title: "Sicherheitslücken in ABB Ability Symphony Plus Engineering ermöglichen Codeausführung"
date: "2026-05-02T08:20:38Z"
original_date: "2026-04-30T12:00:00"
lang: "de"
translationKey: "abb-ability-symphony-plus-engineering-flaws-enable-code-execution"
author: "NewsBot (Validated by Federico Sella)"
description: "CISA warnt vor Schwachstellen in ABB Ability Symphony Plus Engineering aufgrund veralteter PostgreSQL-Version, die eine beliebige Codeausführung auf betroffenen Systemen ermöglichen."
original_url: "https://www.cisa.gov/news-events/ics-advisories/icsa-26-120-06"
source: "CISA"
severity: "High"
target: "ABB Ability Symphony Plus Engineering"
cve: "CVE-2023-5869"
cvss: 8.8
kev: null
tags: ["news", "cybersecurity"]
news-categories: ["cybersecurity"]
layout: "news"
draft: false
---

CISA warnt vor Schwachstellen in ABB Ability Symphony Plus Engineering aufgrund veralteter PostgreSQL-Version, die eine beliebige Codeausführung auf betroffenen Systemen ermöglichen.

{{< cyber-report severity="High" source="CISA" target="ABB Ability Symphony Plus Engineering" cve="CVE-2023-5869" cvss="8.8" >}}

CISA hat eine Warnung (ICSA-26-120-06) veröffentlicht, die mehrere Schwachstellen in ABB Ability Symphony Plus Engineering beschreibt, die auf die Verwendung von PostgreSQL Version 13.11 und früher zurückzuführen sind. Die Fehler umfassen Integer-Überlauf, SQL-Injection, TOCTOU-Race-Condition und Berechtigungsfehler, die es einem authentifizierten Angreifer ermöglichen könnten, beliebigen Code auf dem System auszuführen.

{{< ad-banner >}}

Betroffene Versionen reichen von Ability Symphony Plus 2.2 bis 2.4 SP2 RU1. Die Schwachstellen sind besonders besorgniserregend angesichts des Einsatzes des Produkts in kritischen Infrastruktursektoren wie Chemie, Fertigung, Energie sowie Wasser- und Abwasserwirtschaft weltweit.

Die bemerkenswerteste Schwachstelle, CVE-2023-5869, hat einen CVSS-Score von 8.8 und beinhaltet einen Integer-Überlauf, der durch manipulierte Daten eines authentifizierten PostgreSQL-Benutzers ausgelöst werden kann. Eine erfolgreiche Ausnutzung könnte zu einer vollständigen Systemkompromittierung führen, was die Notwendigkeit sofortiger Patches unterstreicht.

{{< netrunner-insight >}}

Diese Warnung unterstreicht das Risiko veralteter Abhängigkeiten in OT-Umgebungen. SOC-Analysten sollten die Asset-Erkennung für ABB Symphony Plus-Instanzen priorisieren und sicherstellen, dass PostgreSQL über Version 13.11 hinaus aktualisiert wird. DevSecOps-Teams müssen Abhängigkeitsscans in CI/CD-Pipelines für industrielle Steuerungssysteme integrieren, um solche vererbten Schwachstellen frühzeitig zu erkennen.

{{< /netrunner-insight >}}

---

**[Vollständigen Artikel auf CISA lesen ›](https://www.cisa.gov/news-events/ics-advisories/icsa-26-120-06)**
