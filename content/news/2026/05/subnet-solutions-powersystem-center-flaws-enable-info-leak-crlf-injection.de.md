---
title: "Sicherheitslücken im Subnet Solutions PowerSYSTEM Center ermöglichen Informationslecks und CRLF-Injection"
date: "2026-05-13T09:40:06Z"
original_date: "2026-05-12T12:00:00"
lang: "de"
translationKey: "subnet-solutions-powersystem-center-flaws-enable-info-leak-crlf-injection"
author: "NewsBot (Validated by Federico Sella)"
description: "CISA warnt vor mehreren Schwachstellen im Subnet Solutions PowerSYSTEM Center, darunter Informationsoffenlegung und CRLF-Injection, die die Versionen 2020 bis 2026 betreffen."
original_url: "https://www.cisa.gov/news-events/ics-advisories/icsa-26-132-02"
source: "CISA"
severity: "High"
target: "Subnet Solutions PowerSYSTEM Center"
cve: "CVE-2026-35504"
cvss: 8.2
kev: null
tags: ["news", "cybersecurity"]
news-categories: ["cybersecurity"]
layout: "news"
draft: false
---

CISA warnt vor mehreren Schwachstellen im Subnet Solutions PowerSYSTEM Center, darunter Informationsoffenlegung und CRLF-Injection, die die Versionen 2020 bis 2026 betreffen.

{{< cyber-report severity="High" source="CISA" target="Subnet Solutions PowerSYSTEM Center" cve="CVE-2026-35504" cvss="8.2" >}}

CISA hat eine Sicherheitswarnung (ICSA-26-132-02) veröffentlicht, die mehrere Schwachstellen im Subnet Solutions PowerSYSTEM Center beschreibt, einer Plattform, die in kritischen Fertigungs- und Energiesektoren eingesetzt wird. Zu den Schwachstellen gehören eine fehlerhafte Autorisierung (CVE-2026-26289), die es authentifizierten Benutzern mit eingeschränkten Berechtigungen ermöglicht, Gerätekonten zu exportieren und vertrauliche Informationen preiszugeben, die normalerweise Administratoren vorbehalten sind. Darüber hinaus könnten CRLF-Injection-Schwachstellen (CVE-2026-35504, CVE-2026-33570, CVE-2026-35555) es Angreifern ermöglichen, bösartige Header oder Antworten einzuschleusen.

{{< ad-banner >}}

Die betroffenen Versionen umfassen PowerSYSTEM Center 2020 (5.8.x bis 5.28.x), 2024 (6.0.x bis 6.1.x) und 2026 (7.0.x). Die Schwachstellen haben einen CVSS v3-Basiswert von 8.2, was auf eine hohe Schwere hindeutet. Eine erfolgreiche Ausnutzung könnte zu Informationsoffenlegung und möglicher Sitzungsmanipulation oder HTTP-Response-Splitting führen.

Angesichts des Einsatzes des Produkts in kritischen Infrastrukturen weltweit sollten Organisationen der Fehlerbehebung Priorität einräumen. Subnet Solutions hat wahrscheinlich Updates veröffentlicht; Administratoren werden gebeten, die Sicherheitshinweise des Herstellers zu konsultieren und die neuesten Patches anzuwenden. Bis dahin sollte der Netzwerkzugriff auf das PowerSYSTEM Center eingeschränkt und auf anomale Aktivitäten überwacht werden.

{{< netrunner-insight >}}

Für SOC-Analysten: Überwachen Sie Authentifizierungsprotokolle auf ungewöhnliche Gerätekonto-Exporte – dies ist ein deutliches Anzeichen für die Ausnutzung von CVE-2026-26289. DevSecOps-Teams sollten sofort die Versionen des PowerSYSTEM Center inventarisieren und Patches einspielen, da die CRLF-Injection-Vektoren (CVE-2026-35504 et al.) mit anderen Angriffen kombiniert werden könnten, um die Sitzungsintegrität zu gefährden. Behandeln Sie dies aufgrund des CVSS-Scores von 8.2 und der kritischen Sektorexposition als Priorität bei der Behebung.

{{< /netrunner-insight >}}

---

**[Vollständigen Artikel auf CISA lesen ›](https://www.cisa.gov/news-events/ics-advisories/icsa-26-132-02)**
