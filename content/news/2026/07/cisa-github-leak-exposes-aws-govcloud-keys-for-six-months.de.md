---
title: "CISA GitHub-Leck legt AWS GovCloud-Schlüssel für sechs Monate offen"
date: "2026-07-14T09:01:14Z"
original_date: "2026-07-13T15:03:28"
lang: "de"
translationKey: "cisa-github-leak-exposes-aws-govcloud-keys-for-six-months"
slug: "cisa-github-leak-exposes-aws-govcloud-keys-for-six-months"
author: "NewsBot (Validated by Federico Sella)"
description: "Ein Auftragnehmer hat interne CISA-Anmeldedaten, darunter AWS GovCloud-Schlüssel, sechs Monate lang auf GitHub durchsickern lassen. Experten heben kritische Lehren für Sicherheitsteams hervor."
original_url: "https://krebsonsecurity.com/2026/07/lessons-learned-from-cisas-recent-github-leak/"
source: "Krebs on Security"
severity: "High"
target: "CISA GitHub-Repository"
cve: null
cvss: null
kev: null
tags: ["news", "cybersecurity"]
news-categories: ["cybersecurity"]
layout: "news"
draft: false
---

Ein Auftragnehmer hat interne CISA-Anmeldedaten, darunter AWS GovCloud-Schlüssel, sechs Monate lang auf GitHub durchsickern lassen. Experten heben kritische Lehren für Sicherheitsteams hervor.

{{< cyber-report severity="High" source="Krebs on Security" target="CISA GitHub-Repository" >}}

Die Cybersecurity and Infrastructure Security Agency (CISA) hat einen Datenleck gemeldet, bei dem ein Auftragnehmer versehentlich Dutzende interner Anmeldedaten, darunter AWS GovCloud-Schlüssel, in einem öffentlichen GitHub-Repository veröffentlichte. Die Anmeldedaten blieben fast sechs Monate lang offen, bevor KrebsOnSecurity die Behörde benachrichtigte.

{{< ad-banner >}}

Die Nachanalyse von CISA identifizierte Lücken in ihrer ersten Reaktion, wie verzögerte Erkennung und fehlendes automatisiertes Scannen nach Geheimnissen in öffentlichen Repositories. Der Vorfall unterstreicht die Notwendigkeit eines robusten Geheimnismanagements und einer kontinuierlichen Überwachung von Code-Repositories.

Experten empfehlen die Implementierung von Pre-Commit-Hooks, regelmäßigem Secret-Scanning und strengen Zugriffskontrollen, um ähnliche Lecks zu verhindern. Die Verwendung von kurzlebigen Anmeldedaten und automatischer Rotation kann auch die Auswirkungen offengelegter Schlüssel abmildern.

{{< netrunner-insight >}}

Dieser Vorfall ist ein Paradebeispiel dafür, warum Secrets-Scanning in CI/CD-Pipelines integriert werden muss, nicht nur nach dem Commit. SOC-Analysten sollten Warnungen zu öffentlichen Repository-Expositionen priorisieren, und DevSecOps-Teams sollten für Auftragnehmer das Prinzip der geringsten Privilegien durchsetzen. Automatisieren Sie die Rotation von Anmeldedaten und erwägen Sie den Einsatz von Tools wie GitLeaks oder TruffleHog, um Lecks frühzeitig zu erkennen.

{{< /netrunner-insight >}}

---

**[Vollständigen Artikel auf Krebs on Security lesen ›](https://krebsonsecurity.com/2026/07/lessons-learned-from-cisas-recent-github-leak/)**
