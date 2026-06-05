---
title: "Sicherheitslücken in Hitachi Energy RTU500 ermöglichen DoS und beeinträchtigen Verfügbarkeit"
date: "2026-06-05T10:46:09Z"
original_date: "2026-06-04T12:00:00"
lang: "de"
translationKey: "hitachi-energy-rtu500-vulnerabilities-allow-dos-impact-availability"
author: "NewsBot (Validated by Federico Sella)"
description: "CISA warnt vor mehreren Schwachstellen in der Hitachi Energy RTU500-Serie, darunter NULL-Pointer-Dereferenzierung und Endlosschleife, mit CVSS 7.8. Betroffene Versionen aufgelistet."
original_url: "https://www.cisa.gov/news-events/ics-advisories/icsa-26-155-04"
source: "CISA"
severity: "High"
target: "Hitachi Energy RTU500 Serie CMU Firmware"
cve: "CVE-2025-69421"
cvss: 7.8
kev: null
tags: ["news", "cybersecurity"]
news-categories: ["cybersecurity"]
layout: "news"
draft: false
---

CISA warnt vor mehreren Schwachstellen in der Hitachi Energy RTU500-Serie, darunter NULL-Pointer-Dereferenzierung und Endlosschleife, mit CVSS 7.8. Betroffene Versionen aufgelistet.

{{< cyber-report severity="High" source="CISA" target="Hitachi Energy RTU500 Serie CMU Firmware" cve="CVE-2025-69421" cvss="7.8" >}}

Hitachi Energy hat mehrere Schwachstellen offengelegt, die die CMU-Firmware der RTU500-Serie betreffen. Die Fehler umfassen NULL-Pointer-Dereferenzierung, Integer-Überlauf oder -Umlauf sowie eine Schleife mit unerreichbarer Ausstiegsbedingung (Endlosschleife), die zu Denial-of-Service-Bedingungen führen können. Die Ausnutzung beeinträchtigt hauptsächlich die Produktverfügbarkeit, mit potenziellen sekundären Auswirkungen auf Vertraulichkeit und Integrität.

{{< ad-banner >}}

Die von CISA (ICSA-26-155-04) veröffentlichte Warnung listet betroffene Firmware-Versionen von 12.7.1 bis 13.8.1 auf. Mehrere CVEs sind betroffen, darunter CVE-2025-69421, CVE-2026-24515, CVE-2026-25210, CVE-2026-32776, CVE-2026-32777, CVE-2026-32778 und CVE-2026-8479. Die Schwachstellen haben einen CVSS v3-Basiswert von 7.8, was auf eine hohe Schwere hinweist.

Hitachi Energy empfiehlt sofortige Maßnahmen gemäß den Abhilfemaßnahmen der Warnung. Angesichts des Kontexts kritischer Infrastrukturen sollten Organisationen, die betroffene RTU500-Versionen verwenden, das Patchen priorisieren und Netzwerksegmentierung implementieren, um das Ausnutzungsrisiko zu mindern.

{{< netrunner-insight >}}

Diese Schwachstellen sind eine Erinnerung daran, dass OT-Geräte bei Patch-Zyklen oft hinterherhinken. SOC-Teams sollten auf anomalen Datenverkehr zu RTU500-Einheiten achten und sicherstellen, dass diese Geräte von nicht vertrauenswürdigen Netzwerken isoliert sind. DevSecOps-Ingenieure sollten Firmware-Scans in CI/CD-Pipelines integrieren, um bekannte CVEs vor der Bereitstellung zu erkennen.

{{< /netrunner-insight >}}

---

**[Vollständigen Artikel auf CISA lesen ›](https://www.cisa.gov/news-events/ics-advisories/icsa-26-155-04)**
