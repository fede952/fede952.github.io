---
title: "MiniPlasma Windows 0-Day ermöglicht SYSTEM-Privilegieneskalation auf vollständig gepatchten Systemen"
date: "2026-05-18T11:01:35Z"
original_date: "2026-05-18T08:57:34"
lang: "de"
translationKey: "miniplasma-windows-0-day-enables-system-privilege-escalation-on-fully-patched-systems"
author: "NewsBot (Validated by Federico Sella)"
description: "Sicherheitsforscher Chaotic Eclipse veröffentlicht PoC für MiniPlasma, eine Zero-Day-Lücke im Windows Cloud Files Mini Filter Driver (cldflt.sys), die SYSTEM-Berechtigungen auf vollständig gepatchten Systemen gewährt."
original_url: "https://thehackernews.com/2026/05/miniplasma-windows-0-day-enables-system.html"
source: "The Hacker News"
severity: "High"
target: "Windows Cloud Files Mini Filter Driver (cldflt.sys)"
cve: null
cvss: null
kev: null
tags: ["news", "cybersecurity"]
news-categories: ["cybersecurity"]
layout: "news"
draft: false
---

Sicherheitsforscher Chaotic Eclipse veröffentlicht PoC für MiniPlasma, eine Zero-Day-Lücke im Windows Cloud Files Mini Filter Driver (cldflt.sys), die SYSTEM-Berechtigungen auf vollständig gepatchten Systemen gewährt.

{{< cyber-report severity="High" source="The Hacker News" target="Windows Cloud Files Mini Filter Driver (cldflt.sys)" >}}

Chaotic Eclipse, der Sicherheitsforscher hinter den kürzlich offengelegten Windows-Schwachstellen YellowKey und GreenPlasma, hat einen Proof-of-Concept (PoC) für eine Windows-Privilegieneskalation-Zero-Day-Schwachstelle veröffentlicht, die Angreifern SYSTEM-Berechtigungen auf vollständig gepatchten Windows-Systemen gewährt. Die Schwachstelle mit dem Codenamen MiniPlasma betrifft "cldflt.sys", den Windows Cloud Files Mini Filter Driver.

{{< ad-banner >}}

Die Schwachstelle ermöglicht es einem Angreifer mit eingeschränktem Benutzerzugriff, Privilegien auf SYSTEM zu eskalieren, was potenziell eine vollständige Systemkompromittierung ermöglicht. Als Zero-Day ist derzeit kein offizieller Patch verfügbar, sodass vollständig gepatchte Systeme anfällig für Ausnutzung sind, wenn der PoC bewaffnet wird.

Organisationen sollten auf ungewöhnliches Verhalten des cldflt.sys-Treibers achten und zusätzliche Härtungsmaßnahmen in Betracht ziehen, wie die Einschränkung des Zugriffs auf die Cloud Files-Funktion oder die Anwendung temporärer Gegenmaßnahmen, bis ein Patch veröffentlicht wird.

{{< netrunner-insight >}}

SOC-Analysten sollten die Überwachung auf Ausnutzungsversuche gegen cldflt.sys priorisieren, da der PoC die Hürde für Angreifer senkt. DevSecOps-Teams sollten ihre Windows-Image-Härtung überprüfen und erwägen, den Cloud Files Mini Filter Driver zu deaktivieren, falls nicht benötigt, während sie auf einen offiziellen Fix von Microsoft warten.

{{< /netrunner-insight >}}

---

**[Vollständigen Artikel auf The Hacker News lesen ›](https://thehackernews.com/2026/05/miniplasma-windows-0-day-enables-system.html)**
