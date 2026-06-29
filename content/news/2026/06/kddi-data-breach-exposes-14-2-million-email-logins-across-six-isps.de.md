---
title: "KDDI-Datenleck legt 14,2 Millionen E-Mail-Zugänge von sechs ISPs offen"
date: "2026-06-29T11:56:07Z"
original_date: "2026-06-28T14:13:46"
lang: "de"
translationKey: "kddi-data-breach-exposes-14-2-million-email-logins-across-six-isps"
author: "NewsBot (Validated by Federico Sella)"
description: "Der japanische Telekommunikationsanbieter KDDI meldet einen Einbruch in sein E-Mail-System, der fünf weitere ISPs betrifft und bis zu 14,2 Millionen Benutzerdaten gefährdet."
original_url: "https://www.bleepingcomputer.com/news/security/data-breach-exposes-up-to-142-million-email-logins-at-six-isps/"
source: "BleepingComputer"
severity: "High"
target: "E-Mail-Systeme japanischer ISPs"
cve: null
cvss: null
kev: null
tags: ["news", "cybersecurity"]
news-categories: ["cybersecurity"]
layout: "news"
draft: false
---

Der japanische Telekommunikationsanbieter KDDI meldet einen Einbruch in sein E-Mail-System, der fünf weitere ISPs betrifft und bis zu 14,2 Millionen Benutzerdaten gefährdet.

{{< cyber-report severity="High" source="BleepingComputer" target="E-Mail-Systeme japanischer ISPs" >}}

Der japanische Telekommunikationsbetreiber KDDI Corporation hat einen Datenvorfall offengelegt, bei dem Angreifer Zugriff auf eines seiner E-Mail-Systeme erlangten, das von fünf anderen Internetdienstanbietern (ISPs) im Land genutzt wird. Der Vorfall könnte bis zu 14,2 Millionen E-Mail-Zugänge offengelegt haben und betrifft eine erhebliche Anzahl von Nutzern mehrerer Anbieter.

{{< ad-banner >}}

Das kompromittierte System ist Teil der E-Mail-Infrastruktur von KDDI, die als Backend für mehrere ISPs dient. Obwohl die genaue Einbruchsmethode nicht im Detail beschrieben wurde, unterstreicht der Vorfall die Risiken, die mit gemeinsamen Dienstleisterarchitekturen verbunden sind, bei denen ein einzelner Fehlerpunkt auf mehrere Organisationen übergreifen kann.

KDDI hat die betroffenen ISPs benachrichtigt und arbeitet daran, den Vorfall einzudämmen. Benutzern wird empfohlen, Passwörter zu ändern und, wo verfügbar, die Multi-Faktor-Authentifizierung zu aktivieren. Der Vorfall verdeutlicht die Notwendigkeit einer robusten Segmentierung und Überwachung gemeinsamer Infrastrukturkomponenten.

{{< netrunner-insight >}}

Dieser Vorfall ist ein Paradebeispiel für Lieferkettenrisiken in ISP-Ökosystemen. SOC-Analysten sollten die Überwachung auf laterale Bewegungen von E-Mail-Systemen zu anderen kritischen Assets priorisieren, während DevSecOps-Teams strenge Netzwerksegmentierung und Zugriff nach dem Least-Privilege-Prinzip für gemeinsame Backend-Dienste durchsetzen müssen. In den kommenden Wochen ist mit Credential-Stuffing-Angriffen auf diese offengelegten Konten zu rechnen.

{{< /netrunner-insight >}}

---

**[Vollständigen Artikel auf BleepingComputer lesen ›](https://www.bleepingcomputer.com/news/security/data-breach-exposes-up-to-142-million-email-logins-at-six-isps/)**
