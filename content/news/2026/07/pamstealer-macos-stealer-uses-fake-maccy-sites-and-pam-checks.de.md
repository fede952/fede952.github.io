---
title: "PamStealer macOS-Stealer nutzt gefälschte Maccy-Seiten und PAM-Prüfungen"
date: "2026-07-04T09:17:53Z"
original_date: "2026-07-03T08:03:37"
lang: "de"
translationKey: "pamstealer-macos-stealer-uses-fake-maccy-sites-and-pam-checks"
author: "NewsBot (Validated by Federico Sella)"
description: "Jamf Threat Labs entdeckt PamStealer, einen macOS-Info-Stealer, der über gefälschte Maccy-Seiten verbreitet wird und PAM-Prüfungen nutzt, um Anmeldekennwörter zu stehlen."
original_url: "https://thehackernews.com/2026/07/pamstealer-uses-fake-maccy-sites-and.html"
source: "The Hacker News"
severity: "High"
target: "macOS-Benutzer"
cve: null
cvss: null
kev: null
tags: ["news", "cybersecurity"]
news-categories: ["cybersecurity"]
layout: "news"
draft: false
---

Jamf Threat Labs entdeckt PamStealer, einen macOS-Info-Stealer, der über gefälschte Maccy-Seiten verbreitet wird und PAM-Prüfungen nutzt, um Anmeldekennwörter zu stehlen.

{{< cyber-report severity="High" source="The Hacker News" target="macOS-Benutzer" >}}

Cybersicherheitsforscher von Jamf Threat Labs haben einen neuen macOS-Info-Stealer namens PamStealer identifiziert. Die Malware wird als kompilierte AppleScript-Datei (.scpt) verbreitet, die sich als Maccy, einen legitimen Open-Source-Zwischenablagen-Manager, ausgibt. Sie nutzt eine Reihe raffinierter Tricks, um Systeme zu infizieren und sensible Daten, einschließlich Anmeldekennwörter, abzugreifen.

{{< ad-banner >}}

PamStealer verdankt seinen Namen der Fähigkeit, das Pluggable Authentication Module (PAM)-Framework unter macOS zu missbrauchen. Durch das Abfangen von Authentifizierungsprozessen kann es Benutzeranmeldeinformationen erfassen, wenn diese sich anmelden oder für privilegierte Vorgänge authentifizieren. Der Stealer exfiltriert dann die gestohlenen Daten an von Angreifern kontrollierte Server.

Die Kampagne setzt auf gefälschte Websites und Social Engineering, um Benutzer dazu zu verleiten, die schädliche .scpt-Datei herunterzuladen. Nach der Ausführung führt die Malware PAM-Prüfungen durch, um Kennwörter zu ernten, ohne Verdacht zu erregen. Organisationen mit macOS-Endpunkten sollten auf ungewöhnliche .scpt-Dateiausführungen und PAM-bezogene Anomalien achten.

{{< netrunner-insight >}}

Für SOC-Analysten unterstreicht dies die Notwendigkeit, kompilierte AppleScript-Ausführungen und PAM-Modifikationen auf macOS-Endpunkten zu überwachen. DevSecOps-Teams sollten Anwendungs-Whitelisting durchsetzen und Benutzer darüber aufklären, Softwarequellen zu überprüfen, insbesondere bei Zwischenablagen-Managern. Die Implementierung von Endpunkterkennungsregeln für PAM-Missbrauch kann helfen, diesen Stealer frühzeitig zu erkennen.

{{< /netrunner-insight >}}

---

**[Vollständigen Artikel auf The Hacker News lesen ›](https://thehackernews.com/2026/07/pamstealer-uses-fake-maccy-sites-and.html)**
