---
title: "Sicherheitslücken in ABB Terra AC Wallbox ermöglichen Remote-Codeausführung"
date: "2026-05-22T10:24:17Z"
original_date: "2026-05-21T12:00:00"
lang: "de"
translationKey: "abb-terra-ac-wallbox-vulnerabilities-allow-remote-code-execution"
author: "NewsBot (Validated by Federico Sella)"
description: "CISA warnt vor Heap- und Stack-basierten Pufferüberläufen in ABB Terra AC Wallbox (JP) ≤1.8.33; Update auf 1.8.36 behebt CVE-2025-10504, CVE-2025-12142, CVE-2025-12143."
original_url: "https://www.cisa.gov/news-events/ics-advisories/icsa-26-141-05"
source: "CISA"
severity: "Medium"
target: "ABB Terra AC Wallbox (JP)"
cve: "CVE-2025-10504"
cvss: 6.1
kev: null
tags: ["news", "cybersecurity"]
news-categories: ["cybersecurity"]
layout: "news"
draft: false
---

CISA warnt vor Heap- und Stack-basierten Pufferüberläufen in ABB Terra AC Wallbox (JP) ≤1.8.33; Update auf 1.8.36 behebt CVE-2025-10504, CVE-2025-12142, CVE-2025-12143.

{{< cyber-report severity="Medium" source="CISA" target="ABB Terra AC Wallbox (JP)" cve="CVE-2025-10504" cvss="6.1" >}}

ABB hat mehrere Sicherheitslücken in seiner Produktlinie Terra AC Wallbox (JP) offengelegt, die Versionen bis einschließlich 1.8.33 betreffen. Die Schwachstellen umfassen einen heap-basierten Pufferüberlauf (CVE-2025-10504), eine Pufferkopie ohne Überprüfung der Eingabegröße (CVE-2025-12142) und einen stack-basierten Pufferüberlauf (CVE-2025-12143). Eine erfolgreiche Ausnutzung könnte es einem Angreifer ermöglichen, den Heap-Speicher zu beschädigen, was potenziell zur Fernsteuerung des Geräts und unbefugten Schreibvorgängen auf den Flash-Speicher führt und somit das Verhalten der Firmware verändert.

{{< ad-banner >}}

Die Schwachstellen werden mit einem CVSS v3-Basiswert von 6,1 bewertet, was auf eine mittlere Schwere hindeutet. ABB hat die Firmware-Version 1.8.36 veröffentlicht, um diese Probleme zu beheben. Die Produkte sind weltweit im Energiesektor im Einsatz, und der Hersteller empfiehlt, das Update so bald wie möglich anzuwenden.

Obwohl keine aktive Ausnutzung gemeldet wurde, machen das Potenzial für Remote-Codeausführung und Firmware-Manipulation diese Schwachstellen für Betreiber von EV-Ladeinfrastruktur kritisch. Organisationen sollten das Patchen betroffener Geräte priorisieren, insbesondere solcher, die mit unsicheren Netzwerken verbunden sind.

{{< netrunner-insight >}}

Für SOC-Analysten: Überwachen Sie auf anomalen Datenverkehr zu Terra AC Wallbox-Geräten, insbesondere auf unerwartete Schreibvorgänge auf den Flash-Speicher. DevSecOps-Ingenieure sollten strenge Eingabevalidierung in allen benutzerdefinierten Protokollen durchsetzen, die mit dem Ladegerät kommunizieren, und sicherstellen, dass Firmware-Updates zeitnah angewendet werden. Angesichts des CVSS-Scores von 6,1 behandeln Sie diese als mittlere Priorität, aber mit hohem potenziellem Auswirkung aufgrund der Rolle des Geräts in der kritischen Energieinfrastruktur.

{{< /netrunner-insight >}}

---

**[Vollständigen Artikel auf CISA lesen ›](https://www.cisa.gov/news-events/ics-advisories/icsa-26-141-05)**
