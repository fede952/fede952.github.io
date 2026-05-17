---
title: "Siemens Ruggedcom ROX-Sicherheitslücke ermöglicht Root-Dateizugriff durch Argumentinjektion"
date: "2026-05-17T09:01:07Z"
original_date: "2026-05-14T12:00:00"
lang: "de"
translationKey: "siemens-ruggedcom-rox-flaw-allows-root-file-read-via-argument-injection"
author: "NewsBot (Validated by Federico Sella)"
description: "CISA warnt vor CVE-2025-40948, die mehrere Ruggedcom ROX-Geräte betrifft. Ein authentifizierter entfernter Angreifer kann beliebige Dateien mit Root-Rechten lesen. Update auf Version 2.17.1 oder höher."
original_url: "https://www.cisa.gov/news-events/ics-advisories/icsa-26-134-02"
source: "CISA"
severity: "Medium"
target: "Siemens Ruggedcom ROX-Geräte"
cve: "CVE-2025-40948"
cvss: 6.8
kev: null
tags: ["news", "cybersecurity"]
news-categories: ["cybersecurity"]
layout: "news"
draft: false
---

CISA warnt vor CVE-2025-40948, die mehrere Ruggedcom ROX-Geräte betrifft. Ein authentifizierter entfernter Angreifer kann beliebige Dateien mit Root-Rechten lesen. Update auf Version 2.17.1 oder höher.

{{< cyber-report severity="Medium" source="CISA" target="Siemens Ruggedcom ROX-Geräte" cve="CVE-2025-40948" cvss="6.8" >}}

Siemens Ruggedcom ROX-Serien sind von einer Schwachstelle in der Zugriffskontrolle (CVE-2025-40948) betroffen, die es einem authentifizierten entfernten Angreifer ermöglicht, beliebige Dateien mit Root-Rechten aus dem zugrunde liegenden Betriebssystem zu lesen. Der Fehler beruht auf einer unzureichenden Eingabevalidierung in der JSON-RPC-Schnittstelle des Webservers, was eine Argumentinjektion ermöglicht.

{{< ad-banner >}}

Die folgenden Produkte sind betroffen: RUGGEDCOM ROX MX5000, MX5000RE, RX1400, RX1500, RX1501, RX1510, RX1511, RX1512, RX1524, RX1536 und RX5000, alle in Versionen vor 2.17.1. Siemens hat Updates zur Behebung des Problems veröffentlicht und empfiehlt eine sofortige Aktualisierung.

Mit einem CVSS v3-Score von 6,8 wird diese Schwachstelle als mittelschwer eingestuft. Der Angriffsvektor ist netzwerkbasiert, erfordert niedrige Privilegien und keine Benutzerinteraktion. Angesichts der kritischen Infrastruktursektoren (z. B. Fertigung kritischer Güter), in denen diese Geräte eingesetzt werden, könnte eine Ausnutzung zu erheblichen Informationsverlusten führen.

{{< netrunner-insight >}}

Für SOC-Analysten: Priorisieren Sie das Patchen von Ruggedcom ROX-Geräten in Ihrer Umgebung, insbesondere solchen, die ungeschützten Netzwerken ausgesetzt sind. Der authentifizierte Charakter des Exploits verringert das unmittelbare Risiko, schließt es jedoch nicht aus – Angreifer, die ein Konto mit niedrigen Privilegien kompromittieren, können vollen Root-Dateizugriff erlangen. DevSecOps-Teams sollten die Härtung von JSON-RPC-Endpunkten überprüfen und eine Netzwerksegmentierung in Betracht ziehen, um die Angriffsfläche zu begrenzen.

{{< /netrunner-insight >}}

---

**[Vollständigen Artikel auf CISA lesen ›](https://www.cisa.gov/news-events/ics-advisories/icsa-26-134-02)**
