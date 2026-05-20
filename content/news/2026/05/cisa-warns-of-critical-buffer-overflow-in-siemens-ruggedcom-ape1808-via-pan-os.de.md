---
title: "CISA warnt vor kritischem Pufferüberlauf in Siemens RUGGEDCOM APE1808 über PAN-OS"
date: "2026-05-20T10:21:56Z"
original_date: "2026-05-19T12:00:00"
lang: "de"
translationKey: "cisa-warns-of-critical-buffer-overflow-in-siemens-ruggedcom-ape1808-via-pan-os"
author: "NewsBot (Validated by Federico Sella)"
description: "Ein Pufferüberlauf im Palo Alto Networks PAN-OS Captive Portal betrifft Siemens RUGGEDCOM APE1808 Geräte. CVE-2026-0300 ermöglicht nicht authentifizierte Remote-Codeausführung mit Root-Rechten."
original_url: "https://www.cisa.gov/news-events/ics-advisories/icsa-26-139-02"
source: "CISA"
severity: "Critical"
target: "Siemens RUGGEDCOM APE1808 Geräte"
cve: "CVE-2026-0300"
cvss: 10.0
kev: null
tags: ["news", "cybersecurity"]
news-categories: ["cybersecurity"]
layout: "news"
draft: false
---

Ein Pufferüberlauf im Palo Alto Networks PAN-OS Captive Portal betrifft Siemens RUGGEDCOM APE1808 Geräte. CVE-2026-0300 ermöglicht nicht authentifizierte Remote-Codeausführung mit Root-Rechten.

{{< cyber-report severity="Critical" source="CISA" target="Siemens RUGGEDCOM APE1808 Geräte" cve="CVE-2026-0300" cvss="10.0" >}}

CISA hat eine Sicherheitsmeldung (ICSA-26-139-02) veröffentlicht, die eine kritische Pufferüberlauf-Schwachstelle im User-ID Authentication Portal (Captive Portal) Dienst der Palo Alto Networks PAN-OS Software beschreibt. Diese Schwachstelle, verfolgt als CVE-2026-0300 mit einem CVSS-Score von 10.0, ermöglicht es einem nicht authentifizierten Angreifer, beliebigen Code mit Root-Rechten auf PA-Series und VM-Series Firewalls auszuführen, indem er speziell präparierte Pakete sendet.

{{< ad-banner >}}

Die Schwachstelle betrifft Siemens RUGGEDCOM APE1808 Geräte aller Versionen. Siemens bereitet Fix-Versionen vor und empfiehlt die Umsetzung von Workarounds, die in den vorgelagerten Sicherheitsmeldungen von Palo Alto Networks bereitgestellt werden. Bis Patches verfügbar sind, sollten Organisationen den Captive Portal Dienst deaktivieren, falls nicht benötigt, und den Netzwerkzugriff auf betroffene Geräte einschränken.

Angesichts des kritischen CVSS-Scores und des Potenzials für eine vollständige Systemkompromittierung ist sofortiges Handeln erforderlich. Die Sicherheitsmeldung richtet sich an den Sektor Critical Manufacturing, mit weltweit eingesetzten Geräten. Betreiber sollten die Anwendung von Gegenmaßnahmen priorisieren und auf Anzeichen von Ausnutzung achten.

{{< netrunner-insight >}}

Dies ist ein Paradebeispiel für Lieferkettenrisiko: Eine Drittanbieterkomponente (PAN-OS) führt eine kritische Schwachstelle in ein Industrieprodukt ein. SOC-Analysten sollten sofort nach anomalem Datenverkehr zu Captive Portal Ports suchen und sicherstellen, dass die Segmentierung die Gefährdung begrenzt. DevSecOps-Teams müssen alle Instanzen von RUGGEDCOM APE1808 inventarisieren und die vorgelagerten Palo Alto Networks Gegenmaßnahmen unverzüglich anwenden.

{{< /netrunner-insight >}}

---

**[Vollständigen Artikel auf CISA lesen ›](https://www.cisa.gov/news-events/ics-advisories/icsa-26-139-02)**
