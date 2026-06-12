---
title: "CISA warnt vor kritischen Naxclow IoT-Sicherheitslücken, die Geräteübernahme ermöglichen"
date: "2026-06-12T10:59:58Z"
original_date: "2026-06-11T12:00:00"
lang: "de"
translationKey: "cisa-warns-of-critical-naxclow-iot-flaws-allowing-device-takeover"
author: "NewsBot (Validated by Federico Sella)"
description: "Mehrere Schwachstellen in der Naxclow IoT-Plattform, darunter CVE-2026-42947, ermöglichen Geräteentführung und Diebstahl von Anmeldedaten. Betroffen sind intelligente Türklingeln und Heim-Hubs."
original_url: "https://www.cisa.gov/news-events/ics-advisories/icsa-26-162-02"
source: "CISA"
severity: "Critical"
target: "Naxclow IoT-Plattformgeräte"
cve: "CVE-2026-42947"
cvss: 9.8
kev: null
tags: ["news", "cybersecurity"]
news-categories: ["cybersecurity"]
layout: "news"
draft: false
---

Mehrere Schwachstellen in der Naxclow IoT-Plattform, darunter CVE-2026-42947, ermöglichen Geräteentführung und Diebstahl von Anmeldedaten. Betroffen sind intelligente Türklingeln und Heim-Hubs.

{{< cyber-report severity="Critical" source="CISA" target="Naxclow IoT-Plattformgeräte" cve="CVE-2026-42947" cvss="9.8" >}}

CISA hat eine Sicherheitswarnung (ICSA-26-162-02) herausgegeben, die mehrere Schwachstellen in der Naxclow IoT-Plattform beschreibt, die Produkte wie die Smart Doorbell X3, X Smart Home, V720 und ix cam betreffen. Der schwerwiegendste Fehler, CVE-2026-42947, hat einen CVSS-Score von 9,8 und beinhaltet eine Autorisierungsumgehung durch einen benutzergesteuerten Schlüssel, der es einem Angreifer ermöglicht, eine Bestätigungs-Bind-Sequenz erneut abzuspielen, um ein Gerät ohne Benutzerinteraktion stillschweigend einem beliebigen Konto zuzuweisen.

{{< ad-banner >}}

Weitere Schwachstellen umfassen fehlende Autorisierungsprüfungen, die Verwendung hartcodierter kryptografischer Schlüssel, die Erzeugung vorhersagbarer Identifikatoren und das Einfügen vertraulicher Informationen in extern zugängliche Dateien. Eine erfolgreiche Ausnutzung könnte Geräteimitation, Abfangen oder Manipulation der Kommunikation, großflächigen Diebstahl von Anmeldedaten und unbefugten Zugriff auf betroffene Systeme ermöglichen.

Die Schwachstellen betreffen alle Versionen der aufgeführten Produkte, und die Geräte sind weltweit in gewerblichen Einrichtungen im Einsatz. Naxclow mit Hauptsitz in China hat noch keine Patches veröffentlicht. Organisationen, die diese Geräte verwenden, sollten sofort Netzwerksegmentierung und Überwachung implementieren, um anomale Gerätebindungsaktivitäten zu erkennen.

{{< netrunner-insight >}}

Dies ist ein Paradebeispiel für einen Supply-Chain-IoT-Albtraum: hartcodierte Schlüssel, vorhersagbare IDs und ein wiederholbarer Onboarding-Ablauf. SOC-Teams sollten in Protokollen nach unerwarteten Geräteumzuweisungen suchen und erwägen, Naxclow-Geräte bis zum Eintreffen von Patches in einem separaten VLAN zu isolieren. DevSecOps muss auf kryptografische Geräteidentität und gegenseitige Authentifizierung beim IoT-Onboarding drängen.

{{< /netrunner-insight >}}

---

**[Vollständigen Artikel auf CISA lesen ›](https://www.cisa.gov/news-events/ics-advisories/icsa-26-162-02)**
