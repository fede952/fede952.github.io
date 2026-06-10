---
title: "Siemens KACO Blueplanet Wechselrichter anfällig für Ableitung von Anmeldeinformationen"
date: "2026-06-10T10:51:15Z"
original_date: "2026-06-09T12:00:00"
lang: "de"
translationKey: "siemens-kaco-blueplanet-inverters-vulnerable-to-credential-derivation"
author: "NewsBot (Validated by Federico Sella)"
description: "Mehrere Schwachstellen in KACO blueplanet Wechselrichtern ermöglichen Angreifern, aus Seriennummern Anmeldeinformationen abzuleiten und unbefugten Zugriff zu erlangen. Siemens empfiehlt Updates."
original_url: "https://www.cisa.gov/news-events/ics-advisories/icsa-26-160-02"
source: "CISA"
severity: "High"
target: "Siemens KACO Blueplanet Wechselrichter"
cve: null
cvss: null
kev: null
tags: ["news", "cybersecurity"]
news-categories: ["cybersecurity"]
layout: "news"
draft: false
---

Mehrere Schwachstellen in KACO blueplanet Wechselrichtern ermöglichen Angreifern, aus Seriennummern Anmeldeinformationen abzuleiten und unbefugten Zugriff zu erlangen. Siemens empfiehlt Updates.

{{< cyber-report severity="High" source="CISA" target="Siemens KACO Blueplanet Wechselrichter" >}}

CISA hat eine Warnung (ICSA-26-160-02) zu mehreren Schwachstellen in Siemens KACO blueplanet Wechselrichtern veröffentlicht. Diese Fehler könnten es einem Angreifer ermöglichen, aus der Seriennummer eines Geräts Anmeldeinformationen abzuleiten und diese zu missbrauchen, um unbefugten Zugriff auf den Wechselrichter zu erlangen.

{{< ad-banner >}}

Die Warnung deckt eine breite Palette betroffener Modelle ab, darunter blueplanet 100 NX3 M8, 100 TL3 GEN2, 105 TL3 und viele andere, mit Versionen, die als all/* oder spezifische Firmware-Versionen unter 6.1.4.9 aufgeführt sind. KACO new energy GmbH hat Updates für einige Produkte veröffentlicht und bereitet Korrekturen für andere vor, wobei Gegenmaßnahmen empfohlen werden, wo Patches noch nicht verfügbar sind.

In der Warnung werden keine CVE-Identifikatoren oder CVSS-Werte angegeben. Die Schwachstellen gelten als schwerwiegend aufgrund des Potenzials für Remote-Ausnutzung, die zu unbefugtem Gerätezugriff führt, was die Solarenergie-Infrastruktur beeinträchtigen könnte.

{{< netrunner-insight >}}

Für SOC-Analysten und DevSecOps-Ingenieure unterstreicht diese Warnung das Risiko von fest codierten oder ableitbaren Anmeldeinformationen in IoT/OT-Geräten. Inventarisieren Sie sofort betroffene KACO Wechselrichter und wenden Sie Firmware-Updates an, wo verfügbar. Implementieren Sie für nicht gepatchte Einheiten Netzwerksegmentierung und überwachen Sie auf anomale Zugriffsversuche als vorübergehende Gegenmaßnahmen.

{{< /netrunner-insight >}}

---

**[Vollständigen Artikel auf CISA lesen ›](https://www.cisa.gov/news-events/ics-advisories/icsa-26-160-02)**
