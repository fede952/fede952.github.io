---
title: "CISA warnt vor DoS-Schwachstellen in Rockwell Automation CompactLogix Controllern"
date: "2026-06-17T11:46:16Z"
original_date: "2026-06-16T12:00:00"
lang: "de"
translationKey: "cisa-warns-of-dos-vulnerabilities-in-rockwell-automation-compactlogix-controllers"
author: "NewsBot (Validated by Federico Sella)"
description: "Mehrere Schwachstellen in Rockwell Automation CompactLogix 5370 Controllern könnten Denial-of-Service-Angriffe ermöglichen. CVE-2025-11694 ist eine der Schwachstellen."
original_url: "https://www.cisa.gov/news-events/ics-advisories/icsa-26-167-04"
source: "CISA"
severity: "High"
target: "Rockwell Automation CompactLogix 5370 Controller"
cve: "CVE-2025-11694"
cvss: 7.5
kev: null
tags: ["news", "cybersecurity"]
news-categories: ["cybersecurity"]
layout: "news"
draft: false
---

Mehrere Schwachstellen in Rockwell Automation CompactLogix 5370 Controllern könnten Denial-of-Service-Angriffe ermöglichen. CVE-2025-11694 ist eine der Schwachstellen.

{{< cyber-report severity="High" source="CISA" target="Rockwell Automation CompactLogix 5370 Controller" cve="CVE-2025-11694" cvss="7.5" >}}

CISA hat eine Warnung (ICSA-26-167-04) veröffentlicht, die Schwachstellen in Rockwell Automation CompactLogix 5370 Controllern (L1, L2, L3) beschreibt. Die Fehler umfassen eine fehlerhafte Validierung von Integritätsprüfwerten und die Offenlegung sensibler Systeminformationen, die es einem Angreifer ermöglichen könnten, einen Denial-of-Service-Zustand herbeizuführen. Die Warnung betrifft Versionen vor V38.011.

{{< ad-banner >}}

Die bekannteste Schwachstelle, CVE-2025-11694, betrifft die fehlende Validierung von Sequenznummern und Quell-IP-Adressen im CIP-Protokoll. Ein Angreifer kann exponierte Verbindungs-IDs, die auf der Weboberfläche sichtbar sind, ausnutzen, um Denial-of-Service-Angriffe durchzuführen, was zu einem geringfügigen Fehler führt. Der CVSS v3-Score für diese Schwachstelle beträgt 7.5.

Rockwell Automation empfiehlt ein Update auf Version V38.011, um diese Probleme zu beheben. Die betroffenen Produkte sind weltweit im Bereich der Kritischen Fertigung (Critical Manufacturing) im Einsatz. Organisationen sollten die Patches für diese Controller priorisieren, um mögliche Betriebsunterbrechungen zu vermeiden.

{{< netrunner-insight >}}

Für SOC-Analysten: Überwachen Sie auf ungewöhnliche CIP-Datenverkehrsmuster oder wiederholte Verbindungsversuche, die auf CompactLogix-Controller abzielen. DevSecOps-Ingenieure sollten sicherstellen, dass die Weboberfläche nicht mit unsicheren Netzwerken verbunden ist und das Firmware-Update auf V38.011 umgehend anwenden. Dies ist ein einfacher DoS-Vektor, der durch geeignete Netzwerksegmentierung und Patch-Management gemildert werden kann.

{{< /netrunner-insight >}}

---

**[Vollständigen Artikel auf CISA lesen ›](https://www.cisa.gov/news-events/ics-advisories/icsa-26-167-04)**
