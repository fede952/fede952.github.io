---
title: "HollowFrame-Loader und Matryoshka-Backdoor zielen auf Anwaltskanzlei"
date: "2026-08-01T09:01:20Z"
original_date: "2026-07-31T16:39:31"
lang: "de"
translationKey: "hollowframe-loader-and-matryoshka-backdoor-target-law-firm"
slug: "hollowframe-loader-and-matryoshka-backdoor-target-law-firm"
author: "NewsBot (Validated by Federico Sella)"
description: "Der neue Go-basierte Loader HollowFrame und die auf Rust basierende Backdoor Matryoshka werden laut Blackpoint Cyber bei einem Spear-Phishing-Angriff auf eine Anwaltskanzlei eingesetzt."
original_url: "https://thehackernews.com/2026/07/hollowframe-loader-deploys-matryoshka.html"
source: "The Hacker News"
severity: "High"
target: "Anwaltskanzlei"
cve: null
cvss: null
kev: null
tags: ["news", "cybersecurity"]
news-categories: ["cybersecurity"]
layout: "news"
draft: false
---

Der neue Go-basierte Loader HollowFrame und die auf Rust basierende Backdoor Matryoshka werden laut Blackpoint Cyber bei einem Spear-Phishing-Angriff auf eine Anwaltskanzlei eingesetzt.

{{< cyber-report severity="High" source="The Hacker News" target="Anwaltskanzlei" >}}

Blackpoint Cyber hat eine neuartige Angriffskette aufgedeckt, die auf eine Anwaltskanzlei abzielt und mit einer Spear-Phishing-E-Mail beginnt, die den Empfänger dazu verleitet, ein verschlüsseltes Archiv herunterzuladen. Das Archiv enthält eine Windows-Verknüpfungsdatei (LNK), die bei Ausführung einen mehrstufigen Infektionsprozess startet.

{{< ad-banner >}}

Der Angriff nutzt zwei bisher nicht dokumentierte Malware-Familien: HollowFrame, ein Go-basiertes Loader-Framework, und Matryoshka, eine auf Rust basierende Backdoor. Der Loader ist für die Zustellung der Backdoor verantwortlich, die den Angreifern Fernzugriff auf das kompromittierte System ermöglicht.

Diese Kampagne unterstreicht die kontinuierliche Weiterentwicklung von Malware-Tools, wobei Angreifer plattformübergreifende Sprachen wie Go und Rust übernehmen, um der Erkennung zu entgehen und die Analyse zu erschweren. Die Verwendung von verschlüsselten Archiven und LNK-Dateien bei Spear-Phishing ist eine gängige Taktik, aber die Kombination dieser spezifischen Tools fügt eine neue Ebene der Raffinesse hinzu.

{{< netrunner-insight >}}

SOC-Analysten sollten die Überwachung von LNK-Dateiausführungen und Archiv-Downloads aus E-Mail-Links priorisieren, da diese frühe Indikatoren für diese Angriffskette sind. DevSecOps-Teams sollten in Betracht ziehen, die Ausführung von Dateien aus verschlüsselten Archiven zu blockieren oder in einer Sandbox zu testen, und sicherstellen, dass Endpoint Detection and Response (EDR)-Lösungen so konfiguriert sind, dass sie Go- und Rust-Binärdateien erkennen, die Loader-Verhalten aufweisen.

{{< /netrunner-insight >}}

---

**[Vollständigen Artikel auf The Hacker News lesen ›](https://thehackernews.com/2026/07/hollowframe-loader-deploys-matryoshka.html)**
