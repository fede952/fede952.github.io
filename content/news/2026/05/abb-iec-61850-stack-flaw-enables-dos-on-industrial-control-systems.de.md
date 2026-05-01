---
title: "ABB IEC 61850 Stack-Fehler ermöglicht DoS in industriellen Steuerungssystemen"
date: "2026-05-01T09:03:14Z"
original_date: "2026-04-30T12:00:00"
lang: "de"
translationKey: "abb-iec-61850-stack-flaw-enables-dos-on-industrial-control-systems"
author: "NewsBot (Validated by Federico Sella)"
description: "CISA warnt vor einer privat gemeldeten Sicherheitslücke in ABBs IEC 61850 MMS-Implementierung, die System 800xA und Symphony Plus Produkte betrifft und zu Gerätefehlern und Denial-of-Service führt."
original_url: "https://www.cisa.gov/news-events/ics-advisories/icsa-26-120-01"
source: "CISA"
severity: "High"
target: "ABB System 800xA, Symphony Plus IEC 61850"
cve: null
cvss: null
kev: null
tags: ["news", "cybersecurity"]
news-categories: ["cybersecurity"]
layout: "news"
draft: false
---

CISA warnt vor einer privat gemeldeten Sicherheitslücke in ABBs IEC 61850 MMS-Implementierung, die System 800xA und Symphony Plus Produkte betrifft und zu Gerätefehlern und Denial-of-Service führt.

{{< cyber-report severity="High" source="CISA" target="ABB System 800xA, Symphony Plus IEC 61850" >}}

CISA hat eine Warnung (ICSA-26-120-01) zu einer Sicherheitslücke in ABBs Implementierung des IEC 61850-Kommunikationsstacks für MMS-Clientanwendungen herausgegeben. Der Fehler betrifft mehrere Produkte der System 800xA- und Symphony Plus-Reihen, darunter AC800M CI868, Symphony Plus SD Series CI850, PM 877 und S+ Operations. Für eine Ausnutzung ist ein vorheriger Zugang zum IEC 61850-Netzwerk der Anlage erforderlich.

{{< ad-banner >}}

Eine erfolgreiche Ausnutzung verursacht einen Gerätefehler auf PM 877-, CI850- und CI868-Modulen, der einen manuellen Neustart erforderlich macht. Bei S+ Operations-Knoten führt der Angriff zum Absturz des IEC 61850-Kommunikationstreibers, was bei Wiederholung zu einem Denial-of-Service-Zustand führt. Die Gesamtverfügbarkeit und Funktionalität des Knotens bleiben jedoch unbeeinträchtigt, und die GOOSE-Protokollkommunikation ist nicht betroffen. Der System 800xA IEC61850 Connect ist ebenfalls nicht verwundbar.

Betroffene Firmware-Versionen erstrecken sich über mehrere Zweige, darunter S+ Operations bis 6.2.0006.0 und verschiedene PM 877-Versionen. In der Warnung wurden keine CVE-Kennung oder CVSS-Bewertung angegeben. Organisationen, die diese Produkte verwenden, sollten die Warnung prüfen und Maßnahmen wie Netzwerksegmentierung und Zugriffskontrollen ergreifen, um die Exposition gegenüber dem IEC 61850-Netzwerk zu begrenzen.

{{< netrunner-insight >}}

Diese Sicherheitslücke unterstreicht die Bedeutung der Netzwerksegmentierung in OT-Umgebungen. Da für die Ausnutzung ein Zugang zum IEC 61850-Netzwerk erforderlich ist, ist die Isolierung dieses Netzwerks vom Unternehmens-IT und dem Internet entscheidend. SOC-Analysten sollten auf anomale IEC 61850-Datenverkehr achten, während DevSecOps-Ingenieure das Patchen priorisieren und die Implementierung einer Angriffserkennung für MMS-Protokollanomalien in Betracht ziehen sollten.

{{< /netrunner-insight >}}

---

**[Vollständigen Artikel auf CISA lesen ›](https://www.cisa.gov/news-events/ics-advisories/icsa-26-120-01)**
