---
title: "BdThemes-Supply-Chain-Angriff erstellt betrügerische WordPress-Administratoren"
date: "2026-08-11T08:10:19Z"
original_date: "2026-08-11T05:48:44"
lang: "de"
translationKey: "bdthemes-supply-chain-attack-creates-rogue-wordpress-admins"
slug: "bdthemes-supply-chain-attack-creates-rogue-wordpress-admins"
author: "NewsBot (Validated by Federico Sella)"
description: "Supply-Chain-Kompromittierung trifft BdThemes-WordPress-Plugins; kein Quellcode geändert, aber bösartiges JSON erstellt betrügerische Admin-Konten."
original_url: "https://thehackernews.com/2026/08/bdthemes-supply-chain-attack-poisons.html"
source: "The Hacker News"
severity: "High"
target: "WordPress-Websites, die BdThemes-Plugins verwenden"
cve: null
cvss: null
kev: null
tags: ["news", "cybersecurity"]
news-categories: ["cybersecurity"]
layout: "news"
draft: false
---

Supply-Chain-Kompromittierung trifft BdThemes-WordPress-Plugins; kein Quellcode geändert, aber bösartiges JSON erstellt betrügerische Admin-Konten.

{{< cyber-report severity="High" source="The Hacker News" target="WordPress-Websites, die BdThemes-Plugins verwenden" >}}

Cybersecurity-Forscher haben einen Supply-Chain-Angriff auf BdThemes, einen Anbieter von WordPress-Plugins, aufgedeckt. Der Kompromiss führte zur vorübergehenden Deaktivierung von Plugin-Downloads durch das WordPress-Plugins-Team. Bemerkenswerterweise weicht der Angriff von typischen Supply-Chain-Vorfällen ab: Es wurden keine Quelldateien im offiziellen WordPress.org-Repository geändert.

{{< ad-banner >}}

Stattdessen nutzt der Angriff bösartige JSON-Payloads, um betrügerische WordPress-Administratorkonten zu erstellen. Diese Technik ermöglicht es Angreifern, unbefugten Zugriff auf betroffene Websites zu erlangen, ohne die Kern-Plugin-Dateien zu verändern, was die Erkennung durch Standard-Integritätsprüfungen erschwert.

Wordfence-Forscher Paolo Tresso hob die ungewöhnliche Natur des Angriffs hervor und betonte, dass das Fehlen von Quellcode-Änderungen die Notwendigkeit einer umfassenden Supply-Chain-Überwachung über die Code-Integrität hinaus unterstreicht.

{{< netrunner-insight >}}

Dieser Angriff unterstreicht die Bedeutung der Überwachung nicht nur von Codeänderungen, sondern auch von Konfigurations- und Datendateien wie JSON. Für SOC-Analysten: Behandeln Sie Plugin-Updates als risikoreiche Ereignisse und verifizieren Sie die Integrität aller Dateien, nicht nur des Quellcodes. DevSecOps sollte Laufzeitüberwachung für unerwartete Admin-Kontenerstellung implementieren und Dateiintegritätsüberwachung in Betracht ziehen, die Nicht-Code-Assets abdeckt.

{{< /netrunner-insight >}}

---

**[Vollständigen Artikel auf The Hacker News lesen ›](https://thehackernews.com/2026/08/bdthemes-supply-chain-attack-poisons.html)**
