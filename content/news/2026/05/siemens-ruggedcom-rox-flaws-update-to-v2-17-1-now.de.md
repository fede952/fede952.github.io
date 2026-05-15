---
title: "Siemens Ruggedcom ROX-Schwachstellen: Jetzt auf Version 2.17.1 aktualisieren"
date: "2026-05-15T09:41:40Z"
original_date: "2026-05-14T12:00:00"
lang: "de"
translationKey: "siemens-ruggedcom-rox-flaws-update-to-v2-17-1-now"
author: "NewsBot (Validated by Federico Sella)"
description: "CISA warnt vor mehreren Drittanbieter-Schwachstellen in Siemens Ruggedcom ROX vor Version 2.17.1. Über 30 CVEs gelistet, darunter Risiken für Remote-Code-Ausführung. Sofortige Aktualisierung empfohlen."
original_url: "https://www.cisa.gov/news-events/ics-advisories/icsa-26-134-16"
source: "CISA"
severity: "High"
target: "Siemens Ruggedcom ROX-Geräte"
cve: "CVE-2019-13103"
cvss: null
kev: null
tags: ["news", "cybersecurity"]
news-categories: ["cybersecurity"]
layout: "news"
draft: false
---

CISA warnt vor mehreren Drittanbieter-Schwachstellen in Siemens Ruggedcom ROX vor Version 2.17.1. Über 30 CVEs gelistet, darunter Risiken für Remote-Code-Ausführung. Sofortige Aktualisierung empfohlen.

{{< cyber-report severity="High" source="CISA" target="Siemens Ruggedcom ROX-Geräte" cve="CVE-2019-13103" >}}

Siemens Ruggedcom ROX-Versionen vor 2.17.1 enthalten mehrere Drittanbieter-Schwachstellen, wie in der CISA-Warnung ICSA-26-134-16 offengelegt. Zu den betroffenen Produkten gehören die Serien RUGGEDCOM ROX MX5000, MX5000RE und RX1400. Siemens hat aktualisierte Versionen veröffentlicht, um diese Probleme zu beheben, und empfiehlt dringend ein Upgrade auf die neueste Version.

{{< ad-banner >}}

Die Warnung listet über 30 CVEs aus den Jahren 2019 bis 2025 auf, darunter CVE-2019-13103, CVE-2022-2347 und CVE-2025-0395. Obwohl keine spezifischen CVSS-Werte angegeben sind, deuten die Breite und das Alter der Schwachstellen auf eine erhebliche Angriffsfläche hin. Viele dieser CVEs sind mit Drittanbieter-Komponenten verbunden und könnten zu Remote-Code-Ausführung, Denial-of-Service oder Informationsoffenlegung führen.

Organisationen, die betroffene Ruggedcom ROX-Geräte verwenden, sollten das Patchen priorisieren, insbesondere wenn die Geräte ungeschützten Netzwerken ausgesetzt sind. Angesichts der industriellen Natur dieser Produkte könnten ungepatchte Systeme für laterale Bewegungen oder Störungen kritischer Infrastrukturen genutzt werden.

{{< netrunner-insight >}}

Dies ist ein klassischer Fall von angesammelter technischer Schuld in eingebetteten Systemen. SOC-Analysten sollten alle Ruggedcom ROX-Instanzen inventarisieren und die Firmware-Versionen überprüfen. DevSecOps-Teams müssen automatisierte CVE-Scans in ihre CI/CD für Drittanbieter-Abhängigkeiten integrieren. Das Fehlen von CVSS-Werten ist besorgniserregend – gehen Sie vom Schlimmsten aus und behandeln Sie diese als kritisch, bis das Gegenteil bewiesen ist.

{{< /netrunner-insight >}}

---

**[Vollständigen Artikel auf CISA lesen ›](https://www.cisa.gov/news-events/ics-advisories/icsa-26-134-16)**
