---
title: "Fast 800 bösartige npm-Pakete liefern plattformübergreifenden RAT und Infostealer"
date: "2026-08-08T07:43:01Z"
original_date: "2026-08-07T18:48:17"
lang: "de"
translationKey: "nearly-800-malicious-npm-packages-deliver-cross-platform-rat-and-infostealer"
slug: "nearly-800-malicious-npm-packages-deliver-cross-platform-rat-and-infostealer"
author: "NewsBot (Validated by Federico Sella)"
description: "Eine Kampagne mit fast 800 bösartigen npm-Paketen nutzt KI-generierte Typo-Squatting-Namen, um einen plattformübergreifenden RAT und Infostealer zu liefern, der Windows, Mac und Linux angreift."
original_url: "https://thehackernews.com/2026/08/nearly-800-malicious-npm-packages.html"
source: "The Hacker News"
severity: "High"
target: "npm-Registry-Benutzer"
cve: null
cvss: null
kev: null
tags: ["news", "cybersecurity"]
news-categories: ["cybersecurity"]
layout: "news"
draft: false
---

Eine Kampagne mit fast 800 bösartigen npm-Paketen nutzt KI-generierte Typo-Squatting-Namen, um einen plattformübergreifenden RAT und Infostealer zu liefern, der Windows, Mac und Linux angreift.

{{< cyber-report severity="High" source="The Hacker News" target="npm-Registry-Benutzer" >}}

Eine neue Kampagne wurde entdeckt, die fast 800 bösartige Pakete in der npm-Registry veröffentlicht, so ein Bericht des OpenSourceMalware-Forschers Paul. Die Pakete sollen einen plattformübergreifenden Remote-Access-Trojaner (RAT) und Infostealer-Payload liefern, die Windows-, macOS- und Linux-Systeme betrifft.

{{< ad-banner >}}

Die bösartigen Pakete scheinen 'AI-Slop-Squatted' oder zufällig generierte Typo-Squatting-Paketnamen zu verwenden, eine Technik, die KI-generierte Namen nutzt, um der Erkennung zu entgehen und Entwickler dazu zu bringen, sie zu installieren. Nach der Installation bietet der Payload Angreifern Fernzugriff und die Möglichkeit, sensible Informationen von kompromittierten Systemen zu stehlen.

Diese Kampagne unterstreicht das anhaltende Risiko von Lieferkettenangriffen über Paketregistries. Entwickler und Organisationen werden aufgefordert, Paketnamen genau zu prüfen, Herausgeberidentitäten zu verifizieren und automatisierte Sicherheitsscans einzusetzen, um solche bösartigen Pakete zu erkennen und zu blockieren, bevor sie Schaden anrichten können.

{{< netrunner-insight >}}

Für SOC-Analysten und DevSecOps-Ingenieure unterstreicht diese Kampagne die Notwendigkeit einer robusten Paket-Herkunftsprüfung und Laufzeitüberwachung. Implementieren Sie automatisierte Tools, die verdächtige Paketnamen und -verhalten kennzeichnen, und erwägen Sie die Verwendung einer privaten Registry mit strenger Zulassungsliste. Schulen Sie Entwickler außerdem über die Risiken von Typo-Squatting und ermutigen Sie sie, Paketnamen vor der Installation zu überprüfen.

{{< /netrunner-insight >}}

---

**[Vollständigen Artikel auf The Hacker News lesen ›](https://thehackernews.com/2026/08/nearly-800-malicious-npm-packages.html)**
