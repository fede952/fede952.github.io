---
title: "Sleeper-Pakete in Ruby Gems und Go-Modulen zielen auf CI/CD-Pipelines ab"
date: "2026-05-04T09:17:53Z"
original_date: "2026-05-01T09:43:00"
lang: "de"
translationKey: "sleeper-packages-in-ruby-gems-and-go-modules-target-ci-cd-pipelines"
author: "NewsBot (Validated by Federico Sella)"
description: "Angreifer nutzen Sleeper-Pakete, um schädliche Nutzlasten auszuliefern, Anmeldeinformationen zu stehlen, GitHub Actions zu manipulieren und SSH-Persistenz in Software-Lieferkettenangriffen herzustellen."
original_url: "https://thehackernews.com/2026/05/poisoned-ruby-gems-and-go-modules.html"
source: "The Hacker News"
severity: "High"
target: "CI/CD-Pipelines und Software-Lieferketten"
cve: null
cvss: null
kev: null
tags: ["news", "cybersecurity"]
news-categories: ["cybersecurity"]
layout: "news"
draft: false
---

Angreifer nutzen Sleeper-Pakete, um schädliche Nutzlasten auszuliefern, Anmeldeinformationen zu stehlen, GitHub Actions zu manipulieren und SSH-Persistenz in Software-Lieferkettenangriffen herzustellen.

{{< cyber-report severity="High" source="The Hacker News" target="CI/CD-Pipelines und Software-Lieferketten" >}}

Eine neue Kampagne von Angriffen auf die Software-Lieferkette wurde beobachtet, die Sleeper-Pakete als Vehikel nutzt, um anschließend schädliche Nutzlasten zu pushen, die Diebstahl von Anmeldeinformationen, Manipulation von GitHub Actions und SSH-Persistenz ermöglichen. Die Aktivität wird dem GitHub-Konto "BufferZoneCorp" zugeschrieben, das eine Reihe von Repositories veröffentlicht hat, die mit bösartigen Ruby Gems und Go-Modulen in Verbindung stehen.

{{< ad-banner >}}

Der Angriff nutzt zunächst harmlos erscheinende Pakete, die später bösartige Updates erhalten – eine Technik, die als "Sleeper"- oder "trojanisierte" Pakete bekannt ist. Einmal in CI/CD-Umgebungen installiert, stehlen die Nutzlasten Anmeldeinformationen, modifizieren GitHub Actions-Workflows und stellen persistenten SSH-Zugriff her, was eine erhebliche Bedrohung für Entwicklungspipelines darstellt.

Organisationen, die Ruby Gems oder Go-Module aus nicht vertrauenswürdigen Quellen verwenden, sollten ihre Abhängigkeiten prüfen und auf verdächtige Repository-Aktivitäten achten. Die Kampagne unterstreicht die zunehmende Raffinesse von Lieferkettenangriffen, die auf Entwicklerinfrastruktur abzielen.

{{< netrunner-insight >}}

Diese Kampagne unterstreicht die Notwendigkeit strenger Abhängigkeitsfixierung und Integritätsprüfung in CI/CD-Pipelines. SOC-Analysten sollten auf anomale GitHub Actions-Änderungen und SSH-Schlüsselerweiterungen achten, während DevSecOps-Ingenieure das Prinzip der geringsten Privilegien implementieren und die Verwendung von ephemeren Build-Umgebungen in Betracht ziehen sollten, um den Schadensradius zu begrenzen.

{{< /netrunner-insight >}}

---

**[Vollständigen Artikel auf The Hacker News lesen ›](https://thehackernews.com/2026/05/poisoned-ruby-gems-and-go-modules.html)**
