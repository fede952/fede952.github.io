---
title: "Hitachi Energy ITT600 Explorer anfällig für DoS durch libexpat-Schwachstellen"
date: "2026-06-05T10:44:09Z"
original_date: "2026-06-04T12:00:00"
lang: "de"
translationKey: "hitachi-energy-itt600-explorer-vulnerable-to-dos-via-libexpat-flaws"
author: "NewsBot (Validated by Federico Sella)"
description: "CISA warnt vor zwei Schwachstellen in Hitachi Energy ITT600 Explorer, die Denial-of-Service-Angriffe ermöglichen könnten. Betroffen sind Versionen vor 2.1 SP6."
original_url: "https://www.cisa.gov/news-events/ics-advisories/icsa-26-155-02"
source: "CISA"
severity: "High"
target: "Hitachi Energy ITT600 Explorer"
cve: "CVE-2024-8176"
cvss: 7.5
kev: null
tags: ["news", "cybersecurity"]
news-categories: ["cybersecurity"]
layout: "news"
draft: false
---

CISA warnt vor zwei Schwachstellen in Hitachi Energy ITT600 Explorer, die Denial-of-Service-Angriffe ermöglichen könnten. Betroffen sind Versionen vor 2.1 SP6.

{{< cyber-report severity="High" source="CISA" target="Hitachi Energy ITT600 Explorer" cve="CVE-2024-8176" cvss="7.5" >}}

Hitachi Energy hat Schwachstellen in seinem Produkt ITT600 Explorer offengelegt, die insbesondere Versionen vor 2.1 SP6 betreffen. Die als CVE-2024-8176 und CVE-2025-59375 identifizierten Fehler beinhalten unkontrollierte Rekursion und Ressourcenzuweisung ohne Begrenzung oder Drosselung. Diese Probleme können ausgenutzt werden, um einen Denial-of-Service-Zustand (DoS) herbeizuführen.

{{< ad-banner >}}

Die Schwachstellen befinden sich in der von der IEC61850-Funktionalität verwendeten libexpat-Bibliothek. Ein Angreifer mit lokalem Zugriff könnte eine manipulierte IEC61850-Nachricht senden, um einen Stapelüberlauf auszulösen, der neben DoS auch zu Speicherkorruption führen kann. Wichtig: Nur das Produkt ITT600 Explorer ist betroffen; IEC 61850-Systemendpunkte bleiben unbeeinträchtigt.

CISA empfiehlt sofortige Maßnahmen zur Anwendung von Gegenmaßnahmen oder Updates. Das Produkt ist weltweit im Energiesektor im Einsatz, und eine Ausnutzung könnte kritische Infrastrukturbetriebe stören. Organisationen, die betroffene Versionen verwenden, sollten das Patchen priorisieren und die Sicherheitshinweise für detaillierte Abhilfemaßnahmen konsultieren.

{{< netrunner-insight >}}

Für SOC-Analysten: Überwachen Sie auf ungewöhnliche IEC61850-Datenverkehrsmuster, die auf Ausnutzungsversuche hindeuten könnten. DevSecOps-Teams sollten die Aktualisierung von ITT600 Explorer auf Version 2.1 SP6 oder höher priorisieren und eine Netzwerksegmentierung in Betracht ziehen, um den lokalen Zugriff auf das Tool zu beschränken. Angesichts des CVSS-Scores von 7,5 und des Potenzials für Speicherkorruption behandeln Sie dies als Patch mit hoher Priorität.

{{< /netrunner-insight >}}

---

**[Vollständigen Artikel auf CISA lesen ›](https://www.cisa.gov/news-events/ics-advisories/icsa-26-155-02)**
