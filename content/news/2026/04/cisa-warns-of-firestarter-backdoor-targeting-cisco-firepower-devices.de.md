---
title: "CISA warnt vor FIRESTARTER-Hintertür, die auf Cisco Firepower-Geräte abzielt"
date: "2026-04-23T12:00:00"
lang: "de"
translationKey: "cisa-warns-of-firestarter-backdoor-targeting-cisco-firepower-devices"
author: "NewsBot (Validated by Federico Sella)"
description: "CISA und NCSC warnen vor APT-Akteuren, die die FIRESTARTER-Hintertür zur Persistenz auf Cisco ASA/FTD-Geräten nutzen. Dringende Reaktionsmaßnahmen werden beschrieben."
original_url: "https://www.cisa.gov/news-events/analysis-reports/ar26-113a"
source: "CISA"
severity: "High"
target: "Cisco Firepower- und Secure Firewall-Geräte"
cve: null
cvss: null
kev: null
tags: ["news", "cybersecurity"]
news-categories: ["cybersecurity"]
layout: "news"
draft: false
---

CISA und NCSC warnen vor APT-Akteuren, die die FIRESTARTER-Hintertür zur Persistenz auf Cisco ASA/FTD-Geräten nutzen. Dringende Reaktionsmaßnahmen werden beschrieben.

{{< cyber-report severity="High" source="CISA" target="Cisco Firepower- und Secure Firewall-Geräte" >}}

CISA und das britische NCSC haben einen Malware-Analysebericht zur FIRESTARTER-Hintertür veröffentlicht, die von fortschrittlichen Bedrohungsakteuren (APTs) genutzt wird, um auf öffentlich zugänglichen Cisco Firepower- und Secure Firewall-Geräten mit ASA- oder FTD-Software Persistenz zu erlangen. Die Analyse basiert auf einer Probe aus einer forensischen Untersuchung, und CISA hat erfolgreiche Implantate in freier Wildbahn auf Cisco Firepower-Geräten mit ASA-Software bestätigt.

{{< ad-banner >}}

Die Veröffentlichung erfolgt im Rahmen der CISA-Notfalldirektive 25-03, die US-Behörden der FCEB auffordert, Core Dumps zu sammeln und an die CISA-Plattform Malware Next Generation zu übermitteln sowie die Meldungen unverzüglich über das 24/7 Operations Center zu melden. Organisationen wird geraten, bis zur Bekanntgabe weiterer Schritte durch CISA keine zusätzlichen Maßnahmen zu ergreifen.

Während die Malware sowohl für Cisco Firepower- als auch für Secure Firewall-Geräte relevant ist, hat CISA erfolgreiche Implantate nur auf Firepower-Geräten mit ASA beobachtet. Der Bericht betont die Notwendigkeit von Wachsamkeit und proaktiver Suche nach Kompromittierungsindikatoren.

{{< netrunner-insight >}}

SOC-Analysten sollten priorisiert Core Dumps von Cisco ASA/FTD-Geräten sammeln und zur Analyse an CISA übermitteln. DevSecOps-Teams müssen sicherstellen, dass Cisco-Geräte gemäß den Best Practices gepatcht und konfiguriert sind, und auf ungewöhnliche Persistenzmechanismen achten. Diese Hintertür unterstreicht die Kritikalität der Sicherung von Netzwerkrandgeräten gegen Bedrohungen auf APT-Niveau.

{{< /netrunner-insight >}}

---

**[Vollständigen Artikel auf CISA lesen ›](https://www.cisa.gov/news-events/analysis-reports/ar26-113a)**
