---
title: "CISA warnt vor kritischer Authentifizierungsumgehung in Rockwell FactoryTalk Analytics PavilionX"
date: "2026-06-18T11:06:01Z"
original_date: "2026-06-16T12:00:00"
lang: "de"
translationKey: "cisa-warns-of-critical-auth-bypass-in-rockwell-factorytalk-analytics-pavilionx"
author: "NewsBot (Validated by Federico Sella)"
description: "CISA warnt vor CVE-2025-14272, das Rockwell Automation FactoryTalk Analytics PavilionX <7.01 betrifft und unbefugte privilegierte Operationen in kritischen Fertigungsumgebungen ermöglicht."
original_url: "https://www.cisa.gov/news-events/ics-advisories/icsa-26-167-01"
source: "CISA"
severity: "High"
target: "Rockwell FactoryTalk Analytics PavilionX"
cve: "CVE-2025-14272"
cvss: null
kev: null
tags: ["news", "cybersecurity"]
news-categories: ["cybersecurity"]
layout: "news"
draft: false
---

CISA warnt vor CVE-2025-14272, das Rockwell Automation FactoryTalk Analytics PavilionX <7.01 betrifft und unbefugte privilegierte Operationen in kritischen Fertigungsumgebungen ermöglicht.

{{< cyber-report severity="High" source="CISA" target="Rockwell FactoryTalk Analytics PavilionX" cve="CVE-2025-14272" >}}

CISA hat eine Sicherheitswarnung (ICSA-26-167-01) zu einer fehlenden Autorisierungsschwachstelle in Rockwell Automation FactoryTalk Analytics PavilionX veröffentlicht. Der Fehler, der als CVE-2025-14272 verfolgt wird, betrifft Versionen vor 7.01 und ermöglicht einem nicht autorisierten Angreifer die Ausführung privilegierter Operationen wie Benutzer- und Rollenverwaltung.

{{< ad-banner >}}

Die Schwachstelle resultiert aus einer unzureichenden Autorisierungsdurchsetzung in API-Endpunkten. Eine erfolgreiche Ausnutzung könnte zur vollständigen administrativen Kontrolle über das betroffene System führen. Rockwell Automation hat Version 7.01 zur Behebung des Problems veröffentlicht, und Benutzer werden dringend aufgefordert, sofort zu aktualisieren.

Angesichts des Einsatzes dieses Produkts in kritischen Fertigungssektoren weltweit ist das Risiko von Betriebsunterbrechungen oder Datenkompromittierung erheblich. Organisationen sollten das Patchen priorisieren und Zugriffskontrollen überprüfen, um potenzielle Ausnutzung zu mildern.

{{< netrunner-insight >}}

Dies ist eine klassische Autorisierungsumgehung, die als Patch mit hoher Priorität behandelt werden sollte. SOC-Analysten sollten auf anomale API-Aufrufe oder Privilegieneskalationen in PavilionX-Umgebungen achten. DevSecOps-Teams müssen sicherstellen, dass Version 7.01 bereitgestellt wird und dass die Netzwerksegmentierung die Exposition dieser Endpunkte begrenzt.

{{< /netrunner-insight >}}

---

**[Vollständigen Artikel auf CISA lesen ›](https://www.cisa.gov/news-events/ics-advisories/icsa-26-167-01)**
