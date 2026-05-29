---
title: "Kritische Schwachstellen in XCharge C6 EV-Ladegerät ermöglichen Remote-Codeausführung"
date: "2026-05-29T10:39:44Z"
original_date: "2026-05-28T12:00:00"
lang: "de"
translationKey: "critical-flaws-in-xcharge-c6-ev-charger-allow-remote-code-execution"
author: "NewsBot (Validated by Federico Sella)"
description: "CISA warnt vor nicht authentifizierten Schwachstellen in XCharge C6 EV-Ladesteuerungen, einschließlich CVE-2026-9037, mit einem CVSS-Score von 9,8."
original_url: "https://www.cisa.gov/news-events/ics-advisories/icsa-26-148-08"
source: "CISA"
severity: "Critical"
target: "XCharge C6 EV-Ladesteuerungen"
cve: "CVE-2026-9037"
cvss: 9.8
kev: null
tags: ["news", "cybersecurity"]
news-categories: ["cybersecurity"]
layout: "news"
draft: false
---

CISA warnt vor nicht authentifizierten Schwachstellen in XCharge C6 EV-Ladesteuerungen, einschließlich CVE-2026-9037, mit einem CVSS-Score von 9,8.

{{< cyber-report severity="Critical" source="CISA" target="XCharge C6 EV-Ladesteuerungen" cve="CVE-2026-9037" cvss="9.8" >}}

CISA hat eine Sicherheitswarnung (ICSA-26-148-08) veröffentlicht, die mehrere kritische Schwachstellen in XCharge C6 Ladesteuerungen für Elektrofahrzeuge beschreibt. Die Fehler umfassen einen Download von Code ohne Integritätsprüfung (CWE-494), einen stackbasierten Pufferüberlauf und die Initialisierung einer Ressource mit einer unsicheren Standardeinstellung. Eine erfolgreiche Ausnutzung könnte es einem Angreifer ermöglichen, Administratorrechte zu erlangen oder beliebigen Code auf dem Gerät auszuführen.

{{< ad-banner >}}

Die schwerwiegendste Schwachstelle, CVE-2026-9037, betrifft einen Firmware-Update-Mechanismus, der die Authentizität von Firmware-Paketen nicht überprüft. Ohne kryptografische Signaturprüfung könnte ein Angreifer, der den Verwaltungskanal stören oder sich als solcher ausgeben kann, nicht autorisierte Firmware installieren, was zu einer Codeausführung mit hohen Privilegien führt. Der CVSS v3-Score für diese Schwachstelle beträgt 9,8, was auf eine kritische Schwere hinweist.

XCharge hat ab dem 22. Mai 2026 ein Firmware-Update für alle betroffenen Ladegeräte bereitgestellt. Benutzer werden aufgefordert, sicherzustellen, dass ihre Geräte aktualisiert sind, und bei Bedarf den XCharge-Support zu kontaktieren. Das betroffene Produkt ist im Verkehrssektor in mehreren Ländern weit verbreitet.

{{< netrunner-insight >}}

Für SOC-Analysten: Priorisieren Sie die Überwachung der Verwaltungsschnittstellen von XCharge C6-Ladegeräten auf unbefugten Zugriff oder anomale Firmware-Update-Anfragen. DevSecOps-Teams sollten Netzwerksegmentierung durchsetzen und den Hersteller-Patch sofort anwenden, da das Fehlen von Integritätsprüfungen diese Geräte zu einem Hauptziel für Lieferkettenangriffe macht.

{{< /netrunner-insight >}}

---

**[Vollständigen Artikel auf CISA lesen ›](https://www.cisa.gov/news-events/ics-advisories/icsa-26-148-08)**
