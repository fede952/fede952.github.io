---
title: "TrojPix-Angriff exfiltriert Daten aus abgeschotteten Systemen über Videokabel-Emissionen"
date: "2026-07-06T11:24:53Z"
original_date: "2026-07-06T08:50:54"
lang: "de"
translationKey: "trojpix-attack-exfiltrates-data-from-air-gapped-systems-via-video-cable-emissions"
slug: "trojpix-attack-exfiltrates-data-from-air-gapped-systems-via-video-cable-emissions"
author: "NewsBot (Validated by Federico Sella)"
description: "Forscher demonstrieren TrojPix, eine Technik, die Daten von abgeschotteten Computern ableitet, indem sie Bildschirmpixel moduliert, um schwache Funksignale von Videokabeln auszusenden. Dies erfordert vorherigen Malware-Zugriff."
original_url: "https://thehackernews.com/2026/07/new-trojpix-attack-leaks-data-from-air.html"
source: "The Hacker News"
severity: "Medium"
target: "Abgeschottete Systeme"
cve: null
cvss: null
kev: null
tags: ["news", "cybersecurity"]
news-categories: ["cybersecurity"]
layout: "news"
draft: false
---

Forscher demonstrieren TrojPix, eine Technik, die Daten von abgeschotteten Computern ableitet, indem sie Bildschirmpixel moduliert, um schwache Funksignale von Videokabeln auszusenden. Dies erfordert vorherigen Malware-Zugriff.

{{< cyber-report severity="Medium" source="The Hacker News" target="Abgeschottete Systeme" >}}

Forscher der Shandong University haben TrojPix vorgestellt, einen neuartigen Angriff, der Daten aus abgeschotteten Computern durch Ausnutzung elektromagnetischer Emissionen von Videokabeln exfiltriert. Die Technik verändert Bildschirmpixel auf eine für das menschliche Auge nicht wahrnehmbare Weise, sodass das Videokabel ein schwaches Funksignal abstrahlt, das von einem nahegelegenen Empfänger erfasst und dekodiert werden kann.

{{< ad-banner >}}

TrojPix erfordert eine vorherige Malware-Installation auf dem Zielsystem, um Pixelwerte zu manipulieren. Dieser Ansatz erreicht deutlich höhere Datenübertragungsraten im Vergleich zu früheren Air-Gap-Covert-Channels und stellt damit eine praktische Bedrohung für hochsichere Umgebungen dar. Der Angriff verdeutlicht die anhaltende Herausforderung, Daten selbst in physisch isolierten Netzwerken zu schützen.

Obwohl die Technik ausgeklügelt ist, schränkt ihre Abhängigkeit von bereits vorhandener Malware ihre Anwendbarkeit ein. Organisationen sollten sich darauf konzentrieren, eine initiale Kompromittierung durch robuste Endpunktsicherheit zu verhindern und in sensiblen Bereichen auf ungewöhnliche elektromagnetische Emissionen zu achten.

{{< netrunner-insight >}}

Für SOC-Analysten unterstreicht TrojPix, dass abgeschottete Systeme nicht immun gegen Datenexfiltration sind. Überwachen Sie auf anomale elektromagnetische Signale in der Nähe sensibler Workstations und setzen Sie strenge physische Sicherheitsmaßnahmen durch. DevSecOps-Teams sollten in Betracht ziehen, Videokabel abzuschirmen und eine Pixel-basierte Anomalieerkennung zu implementieren, wo dies machbar ist.

{{< /netrunner-insight >}}

---

**[Vollständigen Artikel auf The Hacker News lesen ›](https://thehackernews.com/2026/07/new-trojpix-attack-leaks-data-from-air.html)**
