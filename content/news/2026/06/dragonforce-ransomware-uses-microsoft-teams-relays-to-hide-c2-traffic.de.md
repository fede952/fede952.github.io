---
title: "DragonForce-Ransomware nutzt Microsoft Teams-Relais, um C2-Traffic zu verbergen"
date: "2026-06-16T12:10:12Z"
original_date: "2026-06-16T10:18:48"
lang: "de"
translationKey: "dragonforce-ransomware-uses-microsoft-teams-relays-to-hide-c2-traffic"
author: "NewsBot (Validated by Federico Sella)"
description: "Die DragonForce-Ransomware setzt die benutzerdefinierte Malware 'Backdoor.Turn' ein, um den Command-and-Control-Traffic in der Microsoft Teams-Relaisinfrastruktur zu verbergen."
original_url: "https://www.bleepingcomputer.com/news/security/ransomware-gang-abuses-microsoft-teams-relays-to-hide-malicious-traffic/"
source: "BleepingComputer"
severity: "High"
target: "Microsoft Teams-Relaisinfrastruktur"
cve: null
cvss: null
kev: null
tags: ["news", "cybersecurity"]
news-categories: ["cybersecurity"]
layout: "news"
draft: false
---

Die DragonForce-Ransomware setzt die benutzerdefinierte Malware 'Backdoor.Turn' ein, um den Command-and-Control-Traffic in der Microsoft Teams-Relaisinfrastruktur zu verbergen.

{{< cyber-report severity="High" source="BleepingComputer" target="Microsoft Teams-Relaisinfrastruktur" >}}

Die Ransomware-Gruppe DragonForce wurde dabei beobachtet, wie sie eine benutzerdefinierte Malware namens 'Backdoor.Turn' einsetzt, um ihren Command-and-Control (C2)-Traffic in der Microsoft Teams-Relaisinfrastruktur zu verbergen. Diese Technik ermöglicht es den Angreifern, bösartige Kommunikation mit legitimen Teams-Traffic zu vermischen, was die Erkennung für Netzwerkverteidiger erschwert.

{{< ad-banner >}}

Durch den Missbrauch von Microsoft Teams-Relais kann die Ransomware-Gruppe traditionelle Netzwerksicherheitskontrollen umgehen, die möglicherweise den Traffic zu vertrauenswürdigen Diensten nicht genau prüfen. Die Malware nutzt wahrscheinlich Teams-APIs oder -Protokolle, um C2-Daten zu tunneln, signaturbasierte Erkennung zu umgehen und persistenten Zugriff auf kompromittierte Netzwerke zu ermöglichen.

Organisationen, die Microsoft Teams verwenden, sollten auf ungewöhnliche ausgehende Traffic-Muster zu Teams-Endpunkten achten und die Implementierung zusätzlicher Inspektionen für verschlüsselte Tunnel in Betracht ziehen. Dieser Vorfall unterstreicht den wachsenden Trend von Ransomware-Gruppen, die Living-off-the-Land- und Trusted-Service-Abuse-Techniken anwenden, um der Erkennung zu entgehen.

{{< netrunner-insight >}}

Für SOC-Analysten unterstreicht dies die Notwendigkeit, den normalen Teams-Traffic zu baselinieren und auf Anomalien wie unerwartete Datenmengen oder Verbindungen zu nicht standardmäßigen Teams-Endpunkten zu achten. DevSecOps-Teams sollten Teams-Integrationsberechtigungen überprüfen und unnötigen API-Zugriff einschränken, um die Angriffsfläche für Relais-Missbrauch zu reduzieren.

{{< /netrunner-insight >}}

---

**[Vollständigen Artikel auf BleepingComputer lesen ›](https://www.bleepingcomputer.com/news/security/ransomware-gang-abuses-microsoft-teams-relays-to-hide-malicious-traffic/)**
