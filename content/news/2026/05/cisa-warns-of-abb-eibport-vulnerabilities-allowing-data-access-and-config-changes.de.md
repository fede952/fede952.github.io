---
title: "CISA warnt vor ABB EIBPORT-Sicherheitslücken, die Datenzugriff und Konfigurationsänderungen ermöglichen"
date: "2026-05-29T10:43:33Z"
original_date: "2026-05-28T12:00:00"
lang: "de"
translationKey: "cisa-warns-of-abb-eibport-vulnerabilities-allowing-data-access-and-config-changes"
author: "NewsBot (Validated by Federico Sella)"
description: "ABB EIBPORT-Geräte sind anfällig für Cross-Site-Scripting und Session-ID-Diebstahl. Ein Firmware-Update auf Version 3.9.2 ist verfügbar."
original_url: "https://www.cisa.gov/news-events/ics-advisories/icsa-26-148-03"
source: "CISA"
severity: "High"
target: "ABB EIBPORT-Geräte"
cve: "CVE-2021-22291"
cvss: null
kev: null
tags: ["news", "cybersecurity"]
news-categories: ["cybersecurity"]
layout: "news"
draft: false
---

ABB EIBPORT-Geräte sind anfällig für Cross-Site-Scripting und Session-ID-Diebstahl. Ein Firmware-Update auf Version 3.9.2 ist verfügbar.

{{< cyber-report severity="High" source="CISA" target="ABB EIBPORT-Geräte" cve="CVE-2021-22291" >}}

CISA hat eine Sicherheitswarnung (ICSA-26-148-03) veröffentlicht, die mehrere Schwachstellen in ABB EIBPORT-Geräten beschreibt, insbesondere in den Modellen EIBPORT V3 KNX und EIBPORT V3 KNX GSM. Die Schwachstellen, darunter eine Cross-Site-Scripting (XSS)-Lücke (CWE-79) und ein Problem mit Session-ID-Diebstahl (CVE-2021-22291), könnten einem Angreifer Zugriff auf vertrauliche Informationen auf dem Gerät und die Möglichkeit zur Änderung seiner Konfiguration verschaffen.

{{< ad-banner >}}

Die betroffenen Firmware-Versionen sind solche vor 3.9.2. ABB hat ein Firmware-Update veröffentlicht, um diese privat gemeldeten Schwachstellen zu beheben. Die Produkte sind weltweit in den Bereichen kritische Fertigung und Informationstechnologie im Einsatz, mit dem Hersteller mit Hauptsitz in der Schweiz.

Obwohl in der Warnung kein CVSS-Score angegeben ist, rechtfertigt die potenzielle Auswirkung auf die Integrität und Vertraulichkeit der Geräte eine sofortige Patchen. Organisationen, die betroffene ABB EIBPORT-Geräte verwenden, sollten das Firmware-Update so schnell wie möglich anwenden, um das Risiko einer Ausnutzung zu mindern.

{{< netrunner-insight >}}

Für SOC-Analysten: Priorisieren Sie die Suche nach ABB EIBPORT-Geräten mit Firmware unter 3.9.2 und überwachen Sie auf anomale Konfigurationsänderungen oder Session-Anomalien. DevSecOps-Teams sollten dieses Firmware-Update in ihre Patch-Management-Pipeline integrieren, insbesondere angesichts der Rolle des Geräts in der Gebäudeautomation und kritischen Infrastruktur.

{{< /netrunner-insight >}}

---

**[Vollständigen Artikel auf CISA lesen ›](https://www.cisa.gov/news-events/ics-advisories/icsa-26-148-03)**
