---
title: "CISA warnt vor ABB AWIN Gateway-Schwachstellen, die Neustart und Datenleck ermöglichen"
date: "2026-05-01T08:55:30Z"
original_date: "2026-04-30T12:00:00"
lang: "de"
translationKey: "cisa-warns-of-abb-awin-gateway-flaws-allowing-reboot-data-leak"
author: "NewsBot (Validated by Federico Sella)"
description: "ABB AWIN-Gateways weisen Schwachstellen auf, die Angreifern erlauben, Geräte neu zu starten oder Systemkonfigurationen auszulesen. Die CISA-Warnung ICSA-26-120-05 beschreibt CVE-2025-13777 und Abhilfemaßnahmen."
original_url: "https://www.cisa.gov/news-events/ics-advisories/icsa-26-120-05"
source: "CISA"
severity: "High"
target: "ABB AWIN Gateways"
cve: "CVE-2025-13777"
cvss: 8.3
kev: null
tags: ["news", "cybersecurity"]
news-categories: ["cybersecurity"]
layout: "news"
draft: false
---

ABB AWIN-Gateways weisen Schwachstellen auf, die Angreifern erlauben, Geräte neu zu starten oder Systemkonfigurationen auszulesen. Die CISA-Warnung ICSA-26-120-05 beschreibt CVE-2025-13777 und Abhilfemaßnahmen.

{{< cyber-report severity="High" source="CISA" target="ABB AWIN Gateways" cve="CVE-2025-13777" cvss="8.3" >}}

CISA hat die Warnung ICSA-26-120-05 veröffentlicht, die mehrere Schwachstellen in ABB AWIN-Gateways beschreibt. Die Fehler, darunter Authentifizierungsumgehung durch Capture-Replay und fehlende Authentifizierung für kritische Funktionen, könnten einem nicht authentifizierten Angreifer ermöglichen, das Gerät aus der Ferne neu zu starten oder vertrauliche Systemkonfigurationsdaten abzufragen. Die Schwachstellen betreffen die AWIN-Firmware-Versionen 2.0-0, 2.0-1, 1.2-0 und 1.2-1, die auf der Hardware GW100 rev.2 und GW120 laufen.

{{< ad-banner >}}

Das schwerwiegendste Problem, verfolgt als CVE-2025-13777, ermöglicht eine nicht authentifizierte Abfrage, die die Systemkonfiguration einschließlich sensibler Details offenlegt. Die Warnung weist einen CVSS-v3-Basiswert von 8,3 zu, was auf eine hohe Schwere hinweist. ABB hat die Firmware-Version 2.1-0 für das GW100 rev.2 veröffentlicht, um diese Schwachstellen zu beheben. Organisationen, die betroffene Gateways verwenden, werden aufgefordert, das Update umgehend anzuwenden.

Die Schwachstellen betreffen kritische Fertigungsanlagen, die weltweit eingesetzt werden. Angesichts der Möglichkeit einer Fernausnutzung ohne Authentifizierung stellen diese Fehler ein erhebliches Risiko für Betriebstechnologieumgebungen dar. CISA empfiehlt Benutzern, die vollständige Warnung zu prüfen und Abhilfemaßnahmen umzusetzen, einschließlich Netzwerksegmentierung und Zugriffsbeschränkung auf betroffene Geräte.

{{< netrunner-insight >}}

Für SOC-Analysten: Überwachen Sie auf nicht autorisierte Neustarts oder ungewöhnliche Abfragen an ABB-Gateways; dies sind rauscharme Indikatoren für eine Ausnutzung. DevSecOps-Teams sollten das Patchen auf Firmware 2.1-0 priorisieren und strenge Netzwerkzugriffskontrollen durchsetzen, da die Schwachstellen keine Authentifizierung erfordern und aus der Ferne ausgenutzt werden können.

{{< /netrunner-insight >}}

---

**[Vollständigen Artikel auf CISA lesen ›](https://www.cisa.gov/news-events/ics-advisories/icsa-26-120-05)**
