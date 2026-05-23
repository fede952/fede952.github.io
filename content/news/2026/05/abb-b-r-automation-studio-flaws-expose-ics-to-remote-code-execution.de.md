---
title: "Sicherheitslücken in ABB B&R Automation Studio gefährden ICS durch Remote-Codeausführung"
date: "2026-05-23T09:00:47Z"
original_date: "2026-05-21T12:00:00"
lang: "de"
translationKey: "abb-b-r-automation-studio-flaws-expose-ics-to-remote-code-execution"
author: "NewsBot (Validated by Federico Sella)"
description: "CISA warnt vor 25 Schwachstellen in ABB B&R Automation Studio, darunter kritische CVSS-9.8-Fehler, die unbefugten Zugriff und Remote-Codeausführung ermöglichen könnten."
original_url: "https://www.cisa.gov/news-events/ics-advisories/icsa-26-141-03"
source: "CISA"
severity: "Critical"
target: "ABB B&R Automation Studio"
cve: "CVE-2025-6965"
cvss: 9.8
kev: null
tags: ["news", "cybersecurity"]
news-categories: ["cybersecurity"]
layout: "news"
draft: false
---

CISA warnt vor 25 Schwachstellen in ABB B&R Automation Studio, darunter kritische CVSS-9.8-Fehler, die unbefugten Zugriff und Remote-Codeausführung ermöglichen könnten.

{{< cyber-report severity="Critical" source="CISA" target="ABB B&R Automation Studio" cve="CVE-2025-6965" cvss="9.8" >}}

CISA hat eine Warnung veröffentlicht, die mehrere Schwachstellen in ABB B&R Automation Studio beschreibt, die Versionen vor 6.5 und Version 6.5 betreffen. Die Warnung listet 25 CVEs auf, darunter CVE-2025-6965, CVE-2025-3277 und CVE-2023-7104. Diese Schwachstellen stammen von veralteten Drittanbieterkomponenten und umfassen Probleme wie Heap-basierte Pufferüberläufe, Schreibzugriffe außerhalb der Grenzen, Use-after-Free und unsachgemäße Eingabevalidierung.

{{< ad-banner >}}

Obwohl ABB während der Tests keine Ausnutzung beobachtet hat, könnten die Schwachstellen Angriffsvektoren für unbefugten Zugriff, Datenoffenlegung oder Remote-Codeausführung darstellen. Die schwerwiegendsten CVEs haben einen CVSS-v3-Score von 9,8, was auf kritische Schwere hinweist. Die betroffenen Produkte werden in der industriellen Automatisierung und Steuerungssystemen eingesetzt, was sie zu attraktiven Zielen für Bedrohungsakteure macht.

ABB hat ein Update veröffentlicht, das die veraltete Drittanbieterkomponente ersetzt. Organisationen, die B&R Automation Studio verwenden, werden dringend gebeten, das Update sofort anzuwenden. Angesichts der kritischen Natur dieser Schwachstellen und des Potenzials für Remote-Ausnutzung sollten Anlagenbetreiber das Patchen priorisieren und auf Anzeichen einer Kompromittierung achten.

{{< netrunner-insight >}}

Für SOC-Analysten und DevSecOps-Ingenieure unterstreicht diese Warnung das Risiko von Drittanbieterabhängigkeiten in ICS-Software. Die schiere Anzahl von CVEs (25) deutet auf ein systemisches Problem mit der Komponentenverwaltung hin. Priorisieren Sie die Inventarisierung von B&R Automation Studio-Instanzen und wenden Sie das Update des Herstellers an. Segmentieren Sie außerdem ICS-Netzwerke, um die Gefährdung zu begrenzen, und implementieren Sie Überwachung auf anomales Verhalten, das auf Ausnutzungsversuche hindeuten könnte.

{{< /netrunner-insight >}}

---

**[Vollständigen Artikel auf CISA lesen ›](https://www.cisa.gov/news-events/ics-advisories/icsa-26-141-03)**
