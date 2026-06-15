---
title: "China-nahe Hacker hintertürten Linux-Anmeldesoftware für fast ein Jahrzehnt"
date: "2026-06-15T13:04:59Z"
original_date: "2026-06-12T18:17:55"
lang: "de"
translationKey: "china-linked-hackers-backdoored-linux-login-software-for-nearly-a-decade"
author: "NewsBot (Validated by Federico Sella)"
description: "Eine mit China verbundene Gruppe namens Velvet Ant kompromittierte PAM- und OpenSSH-Komponenten und versteckte sich fast zehn Jahre lang unentdeckt in Linux-Anmeldesystemen."
original_url: "https://thehackernews.com/2026/06/china-linked-hackers-backdoored-linux.html"
source: "The Hacker News"
severity: "High"
target: "Linux-Anmeldesysteme (PAM, OpenSSH)"
cve: null
cvss: null
kev: null
tags: ["news", "cybersecurity"]
news-categories: ["cybersecurity"]
layout: "news"
draft: false
---

Eine mit China verbundene Gruppe namens Velvet Ant kompromittierte PAM- und OpenSSH-Komponenten und versteckte sich fast zehn Jahre lang unentdeckt in Linux-Anmeldesystemen.

{{< cyber-report severity="High" source="The Hacker News" target="Linux-Anmeldesysteme (PAM, OpenSSH)" >}}

Ein mit China verbundener Bedrohungsakteur namens Velvet Ant hat nachweislich zentrale Linux-Anmeldekomponenten, darunter PAM (Pluggable Authentication Modules) und OpenSSH, mit Hintertüren versehen, sodass er fast ein Jahrzehnt lang dauerhaften Zugriff behalten konnte. Die Gruppe zielte auf ein Netzwerk ab, in dem sie ihre Hintertür tief im Authentifizierungsstapel verankerte, was sie resistent gegen standardmäßige Bereinigungsverfahren machte.

{{< ad-banner >}}

Laut der Sicherheitsfirma Sygnia nutzten die Angreifer das Vertrauen in Anmeldesoftware aus, um der Erkennung zu entgehen. Indem sie genau die Mechanismen modifizierten, die den Benutzerzugriff kontrollieren, stellten sie sicher, dass ihr Fußabdruck Systemupdates und routinemäßige Sicherheitsscans überlebte. Die Kampagne unterstreicht die zunehmende Raffinesse staatlich gestützter Gruppen bei der Zielsetzung auf grundlegende Infrastruktur.

Die Kompromittierung unterstreicht die Notwendigkeit für Organisationen, die Integrität kritischer Systemkomponenten über die typische Endpunkterkennung hinaus zu überwachen. Verteidiger sollten Dateiintegritätsüberwachung für PAM-Module und SSH-Binärdateien sowie Verhaltensanalyse von Authentifizierungsprotokollen in Betracht ziehen, um Anomalien zu erkennen, die auf hintertürte Anmeldeprozesse hinweisen.

{{< netrunner-insight >}}

Für SOC-Analysten und DevSecOps-Teams ist dies eine deutliche Erinnerung daran, dass Angreifer die Authentifizierungsebene selbst ins Visier nehmen. Implementieren Sie Laufzeitintegritätsprüfungen für PAM- und OpenSSH-Binärdateien und erwägen Sie den Einsatz von Kernel-Überwachung, um Manipulationen zu erkennen. Überprüfen Sie außerdem SSH-Schlüssel-basierte Authentifizierung und PAM-Konfigurationsänderungen als Teil Ihrer Incident-Response-Playbooks.

{{< /netrunner-insight >}}

---

**[Vollständigen Artikel auf The Hacker News lesen ›](https://thehackernews.com/2026/06/china-linked-hackers-backdoored-linux.html)**
