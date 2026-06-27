---
title: "CISA fügt kritische RCE-Schwachstelle in PTC Windchill dem KEV-Katalog hinzu, während aktive Web-Shell-Angriffe stattfinden"
date: "2026-06-27T09:25:09Z"
original_date: "2026-06-26T12:31:56"
lang: "de"
translationKey: "cisa-adds-ptc-windchill-rce-flaw-to-kev-amid-active-web-shell-attacks"
author: "NewsBot (Validated by Federico Sella)"
description: "CISA fügt eine kritische Remote-Code-Ausführungsschwachstelle in PTC Windchill PDMlink und FlexPLM aufgrund aktiver Ausnutzung dem Katalog bekannter ausgenutzter Schwachstellen hinzu."
original_url: "https://thehackernews.com/2026/06/cisa-adds-exploited-ptc-windchill-rce.html"
source: "The Hacker News"
severity: "Critical"
target: "PTC Windchill PDMlink und FlexPLM"
cve: null
cvss: null
kev: true
tags: ["news", "cybersecurity"]
news-categories: ["cybersecurity"]
layout: "news"
draft: false
---

CISA fügt eine kritische Remote-Code-Ausführungsschwachstelle in PTC Windchill PDMlink und FlexPLM aufgrund aktiver Ausnutzung dem Katalog bekannter ausgenutzter Schwachstellen hinzu.

{{< cyber-report severity="Critical" source="The Hacker News" target="PTC Windchill PDMlink und FlexPLM" kev="true" >}}

Die US-amerikanische Cybersecurity and Infrastructure Security Agency (CISA) hat eine kritische Remote-Code-Ausführungsschwachstelle, die PTC Windchill PDMlink und PTC FlexPLM betrifft, in ihren Katalog bekannter ausgenutzter Schwachstellen (KEV) aufgenommen. Die Entscheidung folgt auf Hinweise auf aktive Ausnutzung, wobei Berichte über laufende Web-Shell-Angriffe auf diese Unternehmenssysteme für Produktdatenmanagement (PDM) und Produktlebenszyklusmanagement (PLM) vorliegen.

{{< ad-banner >}}

Obwohl die spezifische CVE-Kennung in der Ankündigung nicht offengelegt wurde, wird die Schwachstelle als kritischer RCE-Fehler beschrieben, der Angreifern die Ausführung beliebigen Codes auf betroffenen Systemen ermöglichen könnte. Organisationen, die diese Produkte verwenden, werden dringend aufgefordert, Patches zu priorisieren und ihre Umgebungen auf Anzeichen einer Kompromittierung zu überprüfen, da die Ausnutzung zu einer vollständigen Systemübernahme führen kann.

Der KEV-Katalog von CISA dient als verbindliche operative Direktive für Bundesbehörden, die eine Behebung innerhalb bestimmter Fristen erfordert. Organisationen des privaten Sektors wird dringend empfohlen, dies als Bedrohung mit hoher Priorität zu behandeln und Maßnahmen wie Netzwerksegmentierung und Überwachung auf anomale Web-Shell-Aktivitäten zu implementieren.

{{< netrunner-insight >}}

Für SOC-Analysten: Priorisieren Sie die Jagd nach Web-Shell-Indikatoren auf exponierten Windchill-Servern – achten Sie auf ungewöhnliche Kindprozesse, die von der Anwendung erzeugt werden, oder ausgehende Verbindungen zu unbekannten IPs. DevSecOps-Teams sollten sofort verfügbare Patches anwenden und die Bereitstellung von virtuellem Patching oder WAF-Regeln in Betracht ziehen, wenn das Patchen verzögert wird. Dies ist eine Erinnerung daran, dass PLM-Systeme, die im Patch-Management oft übersehen werden, attraktive Ziele für Ransomware-Gruppen sind.

{{< /netrunner-insight >}}

---

**[Vollständigen Artikel auf The Hacker News lesen ›](https://thehackernews.com/2026/06/cisa-adds-exploited-ptc-windchill-rce.html)**
