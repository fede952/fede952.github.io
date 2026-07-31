---
title: "Une faille d'Azure Cosmos DB aurait pu exposer toutes les bases de données"
date: "2026-07-31T09:37:51Z"
original_date: "2026-07-30T13:34:09"
lang: "fr"
translationKey: "azure-cosmos-db-flaw-could-have-exposed-all-databases"
slug: "azure-cosmos-db-flaw-could-have-exposed-all-databases"
author: "NewsBot (Validated by Federico Sella)"
description: "Une vulnérabilité corrigée d'Azure Cosmos DB permettait une évasion de sandbox et un accès inter-locataires aux bases de données, découverte par Wiz sous le nom de CosmosEscape."
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

Une vulnérabilité corrigée d'Azure Cosmos DB permettait une évasion de sandbox et un accès inter-locataires aux bases de données, découverte par Wiz sous le nom de CosmosEscape.

{{< cyber-report severity="High" source="The Hacker News" target="Azure Cosmos DB" >}}

Une vulnérabilité désormais corrigée dans Azure Cosmos DB aurait pu permettre à un attaquant de s'échapper du sandbox de requêtes Gremlin du service et d'obtenir un accès complet en lecture et en écriture aux bases de données des locataires clients. La faille a été découverte par la société de sécurité Wiz, qui a baptisé la chaîne d'exploitation 'CosmosEscape'.

{{< ad-banner >}}

La chaîne d'attaque commençait par une requête conçue contre une base de données Gremlin contrôlée par l'attaquant. De là, l'attaquant pouvait exécuter du code sur l'infrastructure sous-jacente, compromettant potentiellement l'isolation entre les locataires.

Bien que Microsoft ait depuis corrigé le problème, l'incident souligne l'importance critique de l'isolation des locataires dans les services de bases de données cloud. Les organisations utilisant Azure Cosmos DB devraient examiner leurs configurations de sécurité et surveiller toute activité inhabituelle.

{{< netrunner-insight >}}

Pour les analystes SOC, cela souligne la nécessité de surveiller les requêtes Gremlin anormales et les schémas d'accès aux bases de données inhabituels. Les équipes DevSecOps doivent s'assurer que les services de bases de données cloud sont configurés selon le principe du moindre privilège et que les mécanismes de sandboxing sont régulièrement audités. Même si cela est corrigé, des failles similaires peuvent exister dans d'autres services gérés, il est donc essentiel de mener une chasse aux menaces proactive.

{{< /netrunner-insight >}}

---

**[Lire l'article complet sur The Hacker News ›](https://thehackernews.com/2026/07/azure-cosmos-db-flaw-exposed-platform.html)**
