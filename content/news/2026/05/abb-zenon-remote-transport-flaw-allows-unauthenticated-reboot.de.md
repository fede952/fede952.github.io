---
title: "ABB Zenon Remote Transport Schwachstelle ermöglicht nicht authentifizierten Neustart"
date: "2026-05-28T10:50:49Z"
original_date: "2026-05-26T12:00:00"
lang: "de"
translationKey: "abb-zenon-remote-transport-flaw-allows-unauthenticated-reboot"
author: "NewsBot (Validated by Federico Sella)"
description: "CISA warnt vor CVE-2025-8754 in ABB Ability Zenon, die nicht autorisierte Systemneustarts über den Remote Transport Service ermöglicht. Keine aktive Ausnutzung gemeldet."
original_url: "https://www.cisa.gov/news-events/ics-advisories/icsa-26-146-03"
source: "CISA"
severity: "High"
target: "ABB Ability Zenon Systeme"
cve: "CVE-2025-8754"
cvss: 7.5
kev: null
tags: ["news", "cybersecurity"]
news-categories: ["cybersecurity"]
layout: "news"
draft: false
---

CISA warnt vor CVE-2025-8754 in ABB Ability Zenon, die nicht autorisierte Systemneustarts über den Remote Transport Service ermöglicht. Keine aktive Ausnutzung gemeldet.

{{< cyber-report severity="High" source="CISA" target="ABB Ability Zenon Systeme" cve="CVE-2025-8754" cvss="7.5" >}}

CISA hat eine Sicherheitswarnung (ICSA-26-146-03) veröffentlicht, die eine fehlende Authentifizierungsschwachstelle im Remote Transport Service von ABB Ability Zenon beschreibt. Der als CVE-2025-8754 mit einem CVSS-Score von 7,5 eingestufte Fehler ermöglicht es einem Angreifer, ohne gültige Anmeldeinformationen einen Systemneustart auszulösen. Die betroffenen Versionen reichen von 7.50 bis 14.

{{< ad-banner >}}

Die Ausnutzung erfordert vorherigen Netzwerkzugriff, da sich der Angreifer bereits im selben Netzwerk wie das Ziel-Zenon-System befinden muss. ABB weist darauf hin, dass in Standardkonfigurationen der Dienst zensyssrv.exe automatisch startet, Benutzer jedoch ein Passwort für die Nutzung des Remote Transport Service konfigurieren müssen. Zum Zeitpunkt der Veröffentlichung gibt es keine Hinweise auf aktive Ausnutzung in freier Wildbahn.

Die Warnung hebt die breite Bereitstellung von ABB Ability Zenon in kritischen Infrastruktursektoren hervor, darunter Chemie, Energie, Gesundheitswesen sowie Wasser- und Abwassersysteme weltweit. Organisationen, die betroffene Versionen verwenden, sollten sofort die von ABB bereitgestellten Gegenmaßnahmen oder Updates anwenden, um potenzielle Denial-of-Service-Angriffe zu verhindern.

{{< netrunner-insight >}}

Für SOC-Analysten: Priorisieren Sie die Netzwerksegmentierung, um die Exposition von Zenon-Systemen zu begrenzen, und stellen Sie sicher, dass Passwörter für den Remote Transport Service konfiguriert und stark sind. DevSecOps-Teams sollten überprüfen, dass der Dienst zensyssrv.exe nicht mit nicht vertrauenswürdigen Netzwerken verbunden ist, und Hersteller-Patches anwenden, sobald diese verfügbar sind. Angesichts des CVSS-Scores von 7,5 und der Auswirkungen auf kritische Infrastrukturen behandeln Sie dies selbst ohne aktive Ausnutzung als Priorität mit hohem Schweregrad.

{{< /netrunner-insight >}}

---

**[Vollständigen Artikel auf CISA lesen ›](https://www.cisa.gov/news-events/ics-advisories/icsa-26-146-03)**
