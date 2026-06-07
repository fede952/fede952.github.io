---
title: "Miasma-Wurm trifft 73 Microsoft GitHub-Repos in Supply-Chain-Angriff"
date: "2026-06-07T09:57:27Z"
original_date: "2026-06-06T06:58:04"
lang: "de"
translationKey: "miasma-worm-hits-73-microsoft-github-repos-in-supply-chain-attack"
author: "NewsBot (Validated by Federico Sella)"
description: "Microsofts GitHub-Repositories in Azure, Azure-Samples, Microsoft und MicrosoftDocs wurden durch den sich selbst replizierenden Miasma-Wurm kompromittiert, was 73 Repos betrifft."
original_url: "https://thehackernews.com/2026/06/miasma-worm-hits-73-microsoft-github.html"
source: "The Hacker News"
severity: "High"
target: "Microsoft GitHub-Repositories"
cve: null
cvss: null
kev: null
tags: ["news", "cybersecurity"]
news-categories: ["cybersecurity"]
layout: "news"
draft: false
---

Microsofts GitHub-Repositories in Azure, Azure-Samples, Microsoft und MicrosoftDocs wurden durch den sich selbst replizierenden Miasma-Wurm kompromittiert, was 73 Repos betrifft.

{{< cyber-report severity="High" source="The Hacker News" target="Microsoft GitHub-Repositories" >}}

Die sich selbst replizierende Supply-Chain-Angriffskampagne Miasma hat sich auf Microsofts GitHub-Repositories ausgeweitet und 73 Repositories in vier Organisationen kompromittiert: Azure, Azure-Samples, Microsoft und MicrosoftDocs. Der Vorfall wurde von OpenSourceMalware gemeldet, woraufhin GitHub den Zugriff auf die betroffenen Repositories sperrte, um die Ausbreitung einzudämmen.

{{< ad-banner >}}

Dieser Angriff unterstreicht die wachsende Bedrohung durch sich selbst replizierende Malware in Software-Lieferketten. Durch die Kompromittierung vertrauenswürdiger Repositories können Angreifer bösartigen Code in nachgelagerte Projekte einschleusen, die auf diese Quellen angewiesen sind, und so potenziell eine Vielzahl von Benutzern und Organisationen beeinträchtigen.

Während spezifische technische Details der Kompromittierung nicht bekannt gegeben wurden, zeigt der Vorfall die Notwendigkeit verbesserter Sicherheitsmaßnahmen in CI/CD-Pipelines und Repository-Verwaltung. Organisationen sollten ihre Abhängigkeiten von Microsofts GitHub-Repositories überprüfen und auf ungewöhnliche Aktivitäten achten.

{{< netrunner-insight >}}

Für SOC-Analysten: Priorisieren Sie die Überwachung auf ungewöhnliche Commits oder Zugriffsmuster in Ihren eigenen GitHub-Organisationen. DevSecOps-Teams sollten strenge Branch-Schutzregeln durchsetzen, signierte Commits verlangen und automatisierte Scans auf sich selbst replizierende Malware in CI/CD-Pipelines implementieren. Dieser Vorfall ist eine deutliche Erinnerung daran, dass selbst große Anbieter wie Microsoft nicht immun gegen Supply-Chain-Angriffe sind.

{{< /netrunner-insight >}}

---

**[Vollständigen Artikel auf The Hacker News lesen ›](https://thehackernews.com/2026/06/miasma-worm-hits-73-microsoft-github.html)**
