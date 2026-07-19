---
title: "Sieben bösartige npm-Pakete zielen auf Vite-Ökosystem mit Blockchain-C2 ab"
date: "2026-07-19T09:03:59Z"
original_date: "2026-07-17T18:54:51"
lang: "de"
translationKey: "seven-malicious-npm-packages-target-vite-ecosystem-with-blockchain-c2"
slug: "seven-malicious-npm-packages-target-vite-ecosystem-with-blockchain-c2"
author: "NewsBot (Validated by Federico Sella)"
description: "Checkmarx deckt ViteVenom-Kampagne auf, die Blockchain-basierte C2-Infrastruktur nutzt, um über sieben bösartige npm-Pakete, die auf Vite-Frontend-Tooling abzielen, eine RAT auszuliefern."
original_url: "https://thehackernews.com/2026/07/seven-malicious-vite-npm-packages-use.html"
source: "The Hacker News"
severity: "High"
target: "Vite-Frontend-Tooling-Ökosystem"
cve: null
cvss: null
kev: null
tags: ["news", "cybersecurity"]
news-categories: ["cybersecurity"]
layout: "news"
draft: false
---

Checkmarx deckt ViteVenom-Kampagne auf, die Blockchain-basierte C2-Infrastruktur nutzt, um über sieben bösartige npm-Pakete, die auf Vite-Frontend-Tooling abzielen, eine RAT auszuliefern.

{{< cyber-report severity="High" source="The Hacker News" target="Vite-Frontend-Tooling-Ökosystem" >}}

Cybersicherheitsforscher von Checkmarx haben einen Cluster von sieben bösartigen npm-Paketen identifiziert, die auf das Vite-Frontend-Tooling-Ökosystem abzielen, im Rahmen eines Software-Lieferkettenangriffs. Die Kampagne mit dem Codenamen ViteVenom stellt eine Erweiterung der zuvor beobachteten ChainVeil-Operation dar, die eine beispiellose vierstufige Blockchain-basierte Command-and-Control (C2)-Infrastruktur über das Tron-Netzwerk nutzte.

{{< ad-banner >}}

Die bösartigen Pakete sind darauf ausgelegt, ein Remote Access Trojan (RAT) auf kompromittierte Systeme auszuliefern, was Angreifern ermöglicht, Daten zu exfiltrieren und dauerhaften Zugriff aufrechtzuerhalten. Die Nutzung von Blockchain für C2-Kommunikation erschwert Erkennung und Stilllegung, da die Infrastruktur dezentral und resistent gegen traditionelle Sinkholing-Techniken ist.

Organisationen, die Vite in ihren Entwicklungspipelines verwenden, sollten sofort ihre Abhängigkeiten auf die identifizierten bösartigen Pakete überprüfen und strenge Paketintegritätsprüfungen implementieren. Dieser Vorfall unterstreicht die wachsende Raffinesse von Software-Lieferkettenangriffen, bei denen Angreifer legitime Entwicklungswerkzeuge und dezentrale Netzwerke nutzen, um der Erkennung zu entgehen.

{{< netrunner-insight >}}

Für SOC-Analysten kann die Überwachung ausgehender Verbindungen zu Blockchain-Knoten und ungewöhnlicher DNS-Abfragen helfen, diese C2-Technik zu erkennen. DevSecOps-Teams sollten Paketsignierung durchsetzen und Abhängigkeitsscan-Tools verwenden, um bekannte bösartige Pakete zu blockieren, bevor sie in die Build-Pipeline gelangen.

{{< /netrunner-insight >}}

---

**[Vollständigen Artikel auf The Hacker News lesen ›](https://thehackernews.com/2026/07/seven-malicious-vite-npm-packages-use.html)**
