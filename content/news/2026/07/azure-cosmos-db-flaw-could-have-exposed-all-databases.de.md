---
title: "Azure Cosmos DB-Schwachstelle hätte alle Datenbanken offenlegen können"
date: "2026-07-31T09:37:51Z"
original_date: "2026-07-30T13:34:09"
lang: "de"
translationKey: "azure-cosmos-db-flaw-could-have-exposed-all-databases"
slug: "azure-cosmos-db-flaw-could-have-exposed-all-databases"
author: "NewsBot (Validated by Federico Sella)"
description: "Eine gepatchte Azure Cosmos DB-Schwachstelle ermöglichte Sandbox-Escape und mandantenübergreifenden Datenbankzugriff, entdeckt von Wiz als CosmosEscape."
original_url: "https://thehackernews.com/2026/07/azure-cosmos-db-flaw-exposed-platform.html"
source: "The Hacker News"
severity: "High"
target: "Azure Cosmos DB"
cve: null
cvss: null
kev: null
tags: ["news", "cybersecurity"]
news-categories: ["cybersecurity"]
layout: "news"
draft: false
---

Eine gepatchte Azure Cosmos DB-Schwachstelle ermöglichte Sandbox-Escape und mandantenübergreifenden Datenbankzugriff, entdeckt von Wiz als CosmosEscape.

{{< cyber-report severity="High" source="The Hacker News" target="Azure Cosmos DB" >}}

Eine inzwischen gepatchte Schwachstelle in Azure Cosmos DB hätte es einem Angreifer ermöglichen können, die Gremlin-Query-Sandbox des Dienstes zu umgehen und vollständigen Lese- und Schreibzugriff auf Datenbanken über Kundentenants hinweg zu erlangen. Der Fehler wurde von der Sicherheitsfirma Wiz entdeckt, die die Angriffskette unter dem Codenamen 'CosmosEscape' führte.

{{< ad-banner >}}

Die Angriffskette begann mit einer manipulierten Abfrage gegen eine vom Angreifer kontrollierte Gremlin-Datenbank. Von dort aus konnte der Angreifer Codeausführung auf der zugrunde liegenden Infrastruktur erreichen und möglicherweise die Isolierung zwischen den Tenants kompromittieren.

Obwohl Microsoft das Problem inzwischen behoben hat, unterstreicht der Vorfall die kritische Bedeutung der Mandantenisolierung in Cloud-Datenbankdiensten. Organisationen, die Azure Cosmos DB verwenden, sollten ihre Sicherheitskonfigurationen überprüfen und auf ungewöhnliche Aktivitäten achten.

{{< netrunner-insight >}}

Für SOC-Analysten unterstreicht dies die Notwendigkeit, auf anomale Gremlin-Abfragen und ungewöhnliche Datenbankzugriffsmuster zu achten. DevSecOps-Teams sollten sicherstellen, dass Cloud-Datenbankdienste nach dem Prinzip der geringsten Privilegien konfiguriert sind und dass alle Sandbox-Mechanismen regelmäßig überprüft werden. Obwohl dies gepatcht ist, könnten ähnliche Schwachstellen in anderen verwalteten Diensten existieren, daher ist proaktive Bedrohungssuche unerlässlich.

{{< /netrunner-insight >}}

---

**[Vollständigen Artikel auf The Hacker News lesen ›](https://thehackernews.com/2026/07/azure-cosmos-db-flaw-exposed-platform.html)**
