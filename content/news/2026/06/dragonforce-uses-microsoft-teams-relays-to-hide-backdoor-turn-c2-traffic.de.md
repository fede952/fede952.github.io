---
title: "DragonForce nutzt Microsoft Teams-Relais, um Backdoor.Turn-C2-Verkehr zu verbergen"
date: "2026-06-19T11:15:07Z"
original_date: "2026-06-18T13:30:07"
lang: "de"
translationKey: "dragonforce-uses-microsoft-teams-relays-to-hide-backdoor-turn-c2-traffic"
author: "NewsBot (Validated by Federico Sella)"
description: "Die DragonForce-Ransomware-Gruppe setzt eine benutzerdefinierte Go-basierte RAT Backdoor.Turn ein, die C2-Verkehr in Microsoft Teams-Relais verbirgt und ein großes US-Dienstleistungsunternehmen angreift."
original_url: "https://thehackernews.com/2026/06/dragonforce-hackers-abuse-microsoft.html"
source: "The Hacker News"
severity: "High"
target: "Großes US-Dienstleistungsunternehmen"
cve: null
cvss: null
kev: null
tags: ["news", "cybersecurity"]
news-categories: ["cybersecurity"]
layout: "news"
draft: false
---

Die DragonForce-Ransomware-Gruppe setzt eine benutzerdefinierte Go-basierte RAT Backdoor.Turn ein, die C2-Verkehr in Microsoft Teams-Relais verbirgt und ein großes US-Dienstleistungsunternehmen angreift.

{{< cyber-report severity="High" source="The Hacker News" target="Großes US-Dienstleistungsunternehmen" >}}

Bedrohungsakteure der DragonForce-Ransomware-Gruppe wurden dabei beobachtet, wie sie eine benutzerdefinierte Go-basierte Remote Access Trojan (RAT) namens Backdoor.Turn einsetzen, um Command-and-Control (C2)-Verkehr in der Microsoft Teams-Relais-Infrastruktur zu verbergen. Die Hintertür wurde gegen ein großes US-Dienstleistungsunternehmen eingesetzt, wie Erkenntnisse von Broadcom-eigenem Symantec und Carbon Black zeigen.

{{< ad-banner >}}

Durch die Nutzung legitimer Microsoft Teams-Relais können die Angreifer bösartigen Verkehr mit normaler Geschäftskommunikation vermischen, was die Erkennung für Netzwerkverteidiger erschwert. Die Go-basierte RAT verschafft den Angreifern persistenten Zugriff und die Fähigkeit, Befehle auszuführen, Daten zu exfiltrieren und zusätzliche Nutzlasten zu deployen.

Diese Technik unterstreicht die sich entwickelnden Taktiken von Ransomware-Gruppen, um traditionelle Netzwerküberwachungstools zu umgehen. Organisationen, die Microsoft Teams nutzen, sollten ihre Sicherheitskonfigurationen überprüfen und auf anomale Relais-Verkehrsmuster achten.

{{< netrunner-insight >}}

SOC-Analysten sollten auf ungewöhnlichen Microsoft Teams-Relais-Verkehr achten, insbesondere von nicht standardmäßigen Endpunkten oder außerhalb der Geschäftszeiten. DevSecOps-Teams sollten strenge Anwendungs-Allowlisting durchsetzen und Teams-Verkehr auf verschlüsselte Tunnel prüfen, die auf C2-Kommunikation hindeuten könnten. Dieser Angriff unterstreicht die Notwendigkeit von Zero-Trust-Prinzipien selbst für vertrauenswürdige Kollaborationsplattformen.

{{< /netrunner-insight >}}

---

**[Vollständigen Artikel auf The Hacker News lesen ›](https://thehackernews.com/2026/06/dragonforce-hackers-abuse-microsoft.html)**
