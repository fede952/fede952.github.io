---
title: "CISA warnt vor Schwachstelle in ABB-Türöffner, die physische Zugangsumgehung ermöglicht"
date: "2026-05-30T09:11:24Z"
original_date: "2026-05-28T12:00:00"
lang: "de"
translationKey: "cisa-warns-of-abb-door-opener-flaw-allowing-physical-access-bypass"
author: "NewsBot (Validated by Federico Sella)"
description: "Die CISA-Warnung ICSA-26-148-04 beschreibt eine Authentifizierungsumgehungsschwachstelle (CVE-2025-7705) im ABB Busch-Welcome 2 Wire Türöffneraktor, die unbefugten Gebäudezugang ermöglicht."
original_url: "https://www.cisa.gov/news-events/ics-advisories/icsa-26-148-04"
source: "CISA"
severity: "Medium"
target: "ABB Busch-Welcome 2 Wire Türöffneraktor"
cve: "CVE-2025-7705"
cvss: 6.8
kev: null
tags: ["news", "cybersecurity"]
news-categories: ["cybersecurity"]
layout: "news"
draft: false
---

Die CISA-Warnung ICSA-26-148-04 beschreibt eine Authentifizierungsumgehungsschwachstelle (CVE-2025-7705) im ABB Busch-Welcome 2 Wire Türöffneraktor, die unbefugten Gebäudezugang ermöglicht.

{{< cyber-report severity="Medium" source="CISA" target="ABB Busch-Welcome 2 Wire Türöffneraktor" cve="CVE-2025-7705" cvss="6.8" >}}

CISA hat die Warnung ICSA-26-148-04 zu einer Authentifizierungsumgehungsschwachstelle im ABB Busch-Welcome 2 Wire Türöffneraktor veröffentlicht, die als CVE-2025-7705 identifiziert wurde. Der Fehler beruht auf einem standardmäßig aktivierten Kompatibilitätsmodus, der es einem Angreifer ermöglicht, physischen, unbefugten Zugang zu Gebäuden zu erlangen, in denen das betroffene Produkt installiert ist. Die Schwachstelle betrifft alle Versionen des Schaltaktors 4 DU und des Schaltaktors Tür/Licht 4 DU.

{{< ad-banner >}}

Der CVSS v3-Basiswert für diese Schwachstelle beträgt 6,8, was auf eine mittlere Schwere hindeutet. ABB hat Abhilfemaßnahmen bereitgestellt, die das Umschalten des Modusschalters am Produkt und einen Stromreset zur Neukalibrierung des Systems umfassen. Das Produkt ist weltweit im Einsatz, hauptsächlich in gewerblichen Einrichtungen, und der Hersteller hat seinen Sitz in der Schweiz.

Organisationen, die die betroffenen ABB Busch-Welcome-Systeme verwenden, sollten die empfohlenen Abhilfemaßnahmen sofort umsetzen. Angesichts der physischen Sicherheitsimplikationen stellt diese Schwachstelle ein erhebliches Risiko für die Gebäudezugangskontrolle dar. Sicherheitsteams sollten sicherstellen, dass die Neukalibrierungsschritte korrekt ausgeführt werden, und auf Anzeichen einer Ausnutzung achten.

{{< netrunner-insight >}}

Diese Schwachstelle ist eine deutliche Erinnerung daran, dass IoT- und Gebäudeautomationsgeräte oft mit unsicheren Standardeinstellungen ausgeliefert werden. SOC-Analysten sollten die Asset-Erkennung für ABB Busch-Welcome-Systeme priorisieren und sicherstellen, dass die manuelle Neukalibrierung angewendet wird. DevSecOps-Teams müssen sich für sichere-by-Design-Prinzipien einsetzen, insbesondere bei Geräten, die den physischen Zugang steuern.

{{< /netrunner-insight >}}

---

**[Vollständigen Artikel auf CISA lesen ›](https://www.cisa.gov/news-events/ics-advisories/icsa-26-148-04)**
