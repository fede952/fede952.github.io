---
title: "ABB B&R-PCs von mehreren CVEs betroffen: RCE, DoS, DNS-Vergiftung"
date: "2026-05-22T10:21:58Z"
original_date: "2026-05-21T12:00:00"
lang: "de"
translationKey: "abb-b-r-pcs-hit-by-multiple-cves-rce-dos-dns-poisoning"
author: "NewsBot (Validated by Federico Sella)"
description: "CISA warnt vor Schwachstellen in ABB B&R Industrie-PCs. Ein Update ist verfügbar. Angreifer können Remote-Code-Ausführung, DoS, DNS-Cache-Vergiftung oder Datendiebstahl erreichen."
original_url: "https://www.cisa.gov/news-events/ics-advisories/icsa-26-141-02"
source: "CISA"
severity: "High"
target: "ABB B&R Industrie-PCs"
cve: "CVE-2023-45229"
cvss: null
kev: null
tags: ["news", "cybersecurity"]
news-categories: ["cybersecurity"]
layout: "news"
draft: false
---

CISA warnt vor Schwachstellen in ABB B&R Industrie-PCs. Ein Update ist verfügbar. Angreifer können Remote-Code-Ausführung, DoS, DNS-Cache-Vergiftung oder Datendiebstahl erreichen.

{{< cyber-report severity="High" source="CISA" target="ABB B&R Industrie-PCs" cve="CVE-2023-45229" >}}

ABB hat Schwachstellen offengelegt, die mehrere B&R Industrie-PC-Produktlinien betreffen, darunter APC4100, APC910, C80, MPC3100, PPC1200, PPC900 und APC2200. Die als CVE-2023-45229 bis CVE-2023-45237 verfolgten Fehler ermöglichen netzwerkbasierten Angreifern, Remote-Code auszuführen, Denial-of-Service-Angriffe zu starten, DNS-Caches zu vergiften oder vertrauliche Informationen zu extrahieren.

{{< ad-banner >}}

Die Sicherheitswarnung listet betroffene Versionen für jedes Produkt auf, wobei Updates zur Behebung der Probleme verfügbar sind. Beispielsweise sind APC4100-Versionen unter 1.09 anfällig, während Version 1.09 gepatcht ist. Ebenso sind APC910-Versionen bis einschließlich 1.25 betroffen. ABB empfiehlt, sofort auf die neuesten Firmware-Versionen zu aktualisieren.

Angesichts des Kontexts industrieller Steuerungssysteme (ICS) stellen diese Schwachstellen erhebliche Risiken für Betriebstechnologieumgebungen dar. Organisationen, die betroffene ABB B&R-PCs verwenden, sollten das Patchen priorisieren, insbesondere wenn die Geräte ungeschützten Netzwerken ausgesetzt sind.

{{< netrunner-insight >}}

Für SOC-Analysten: Überwachen Sie den Netzwerkverkehr auf anomale DNS-Abfragen oder unerwartete Verbindungen von B&R-PCs. DevSecOps-Teams sollten alle betroffenen Geräte inventarisieren und die Firmware-Updates so schnell wie möglich einspielen, da diese CVEs Remote-Code-Ausführung ohne Authentifizierung ermöglichen. Erwägen Sie die Segmentierung von ICS-Netzwerken, um die Exposition zu begrenzen.

{{< /netrunner-insight >}}

---

**[Vollständigen Artikel auf CISA lesen ›](https://www.cisa.gov/news-events/ics-advisories/icsa-26-141-02)**
