---
title: "Neuer MODBEACON-RAT nutzt gRPC-Streaming für verschlüsselten C2-Verkehr"
date: "2026-07-11T08:43:59Z"
original_date: "2026-07-10T13:15:23"
lang: "de"
translationKey: "new-modbeacon-rat-uses-grpc-streaming-for-encrypted-c2-traffic"
slug: "new-modbeacon-rat-uses-grpc-streaming-for-encrypted-c2-traffic"
author: "NewsBot (Validated by Federico Sella)"
description: "Die mit China verbundene Gruppe Silver Fox setzt den Rust-basierten MODBEACON-RAT mittels SEO-Poisoning ein und verwendet gRPC-Streaming für verschlüsselte C2-Kommunikation."
original_url: "https://thehackernews.com/2026/07/new-modbeacon-rat-uses-grpc-streaming.html"
source: "The Hacker News"
severity: "High"
target: "Windows-Nutzer über gefälschte Installationsprogramme"
cve: null
cvss: null
kev: null
tags: ["news", "cybersecurity"]
news-categories: ["cybersecurity"]
layout: "news"
draft: false
---

Die mit China verbundene Gruppe Silver Fox setzt den Rust-basierten MODBEACON-RAT mittels SEO-Poisoning ein und verwendet gRPC-Streaming für verschlüsselte C2-Kommunikation.

{{< cyber-report severity="High" source="The Hacker News" target="Windows-Nutzer über gefälschte Installationsprogramme" >}}

Der mit China verbundenen Cyberkriminalitätsgruppe Silver Fox wird ein neuer Rust-basierter Trojaner für den Fernzugriff (RAT) namens MODBEACON zugeschrieben. Die Malware nutzt gRPC-Streaming für verschlüsselten Command-and-Control (C2)-Verkehr, was die Erkennung erschwert.

{{< ad-banner >}}

Laut dem chinesischen Cybersicherheitsunternehmen QiAnXin verbreitet Silver Fox MODBEACON über gefälschte Installationsprogramme mittels SEO-Poisoning-Techniken. Obwohl die Gruppe wie ein wenig ausgeklügelter, aber sehr aktiver Akteur erscheinen mag, sind ihre tatsächlichen organisatorischen Fähigkeiten fortgeschrittener.

Die Verwendung von gRPC-Streaming für die C2-Kommunikation stellt eine neuartige Technik für Malware dar, da sie HTTP/2 und Protocol Buffers nutzt, um sich in legitimen Datenverkehr einzufügen. Sicherheitsteams sollten auf ungewöhnlichen gRPC-Verkehr achten und durch SEO-Poisoning kompromittierte Download-Seiten untersuchen.

{{< netrunner-insight >}}

SOC-Analysten sollten die Analyse von gRPC-Verkehr in ihre Erkennungspipelines aufnehmen, da MODBEACONs Nutzung von Streaming-RPCs traditionelle Netzwerksignaturen umgehen kann. DevSecOps-Teams müssen die Integrität von Softwaredownloads überprüfen und erwägen, bekannte SEO-Poisoning-Domains zu blockieren. Dieser RAT unterstreicht die Notwendigkeit proaktiver Bedrohungsjagd gegen Rust-basierte Malware.

{{< /netrunner-insight >}}

---

**[Vollständigen Artikel auf The Hacker News lesen ›](https://thehackernews.com/2026/07/new-modbeacon-rat-uses-grpc-streaming.html)**
