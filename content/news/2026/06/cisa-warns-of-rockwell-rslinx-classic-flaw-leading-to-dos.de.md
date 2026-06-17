---
title: "CISA warnt vor Rockwell RSLinx Classic-Sicherheitslücke, die zu DoS führen kann"
date: "2026-06-17T11:42:55Z"
original_date: "2026-06-16T12:00:00"
lang: "de"
translationKey: "cisa-warns-of-rockwell-rslinx-classic-flaw-leading-to-dos"
author: "NewsBot (Validated by Federico Sella)"
description: "CISA-Beratungshinweis hebt CVE-2020-13573 hervor, einen stack-basierten Pufferüberlauf in Rockwell Automation RSLinx Classic ≤4.50.00, der Denial-of-Service und Remote-Codeausführung riskiert."
original_url: "https://www.cisa.gov/news-events/ics-advisories/icsa-26-167-02"
source: "CISA"
severity: "High"
target: "Rockwell Automation RSLinx Classic"
cve: "CVE-2020-13573"
cvss: 7.5
kev: null
tags: ["news", "cybersecurity"]
news-categories: ["cybersecurity"]
layout: "news"
draft: false
---

CISA-Beratungshinweis hebt CVE-2020-13573 hervor, einen stack-basierten Pufferüberlauf in Rockwell Automation RSLinx Classic ≤4.50.00, der Denial-of-Service und Remote-Codeausführung riskiert.

{{< cyber-report severity="High" source="CISA" target="Rockwell Automation RSLinx Classic" cve="CVE-2020-13573" cvss="7.5" >}}

CISA hat einen Beratungshinweis (ICSA-26-167-02) zu einer Sicherheitslücke in Rockwell Automation RSLinx Classic veröffentlicht, einer weit verbreiteten industriellen Kommunikationssoftware. Der als CVE-2020-13573 identifizierte Fehler ist ein stack-basierter Pufferüberlauf, der aus der Ferne ausgenutzt werden kann, um beliebigen Code auszuführen oder einen Denial-of-Service zu verursachen, wodurch die Anwendung nicht mehr reagiert und sich nicht automatisch erholen kann.

{{< ad-banner >}}

Die betroffenen Versionen umfassen RSLinx Classic bis einschließlich Version 4.50.00. Die Sicherheitslücke hat einen CVSS v3-Score von 7,5, was auf eine hohe Schwere hinweist. Rockwell Automation empfiehlt ein Upgrade auf Version 4.60.00 oder höher oder die Anwendung des Patches BF31213 für Kunden, die kein sofortiges Upgrade durchführen können. Der Beratungshinweis verweist auch auf CWE-125 (Out-of-bounds Read) als zugrunde liegende Schwachstelle.

Angesichts der betroffenen kritischen Infrastruktursektoren – Fertigung, Energie, Lebensmittel und Landwirtschaft sowie Wasser und Abwasser – und der globalen Verbreitung des Produkts ist eine zeitnahe Patchen unerlässlich. Organisationen sollten dieses Update priorisieren, um das Risiko einer Ausnutzung zu mindern, insbesondere in Umgebungen, in denen RSLinx Classic ungeschützten Netzwerken ausgesetzt ist.

{{< netrunner-insight >}}

Für SOC-Analysten: Überwachen Sie auf ungewöhnliche Abstürze oder Reaktionslosigkeit in RSLinx Classic-Prozessen, da dies auf Ausnutzungsversuche hindeuten kann. DevSecOps-Teams sollten sofort das Upgrade auf Version 4.60.00 planen oder Patch BF31213 anwenden und sicherstellen, dass RSLinx-Instanzen nicht direkt aus dem Internet erreichbar sind. Angesichts des CVSS-Scores und des Potenzials für Remote-Codeausführung behandeln Sie dies als ein Element mit hoher Priorität.

{{< /netrunner-insight >}}

---

**[Vollständigen Artikel auf CISA lesen ›](https://www.cisa.gov/news-events/ics-advisories/icsa-26-167-02)**
