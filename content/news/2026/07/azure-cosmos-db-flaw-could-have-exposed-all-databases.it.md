---
title: "La vulnerabilità di Azure Cosmos DB avrebbe potuto esporre tutti i database"
date: "2026-07-31T09:37:51Z"
original_date: "2026-07-30T13:34:09"
lang: "it"
translationKey: "azure-cosmos-db-flaw-could-have-exposed-all-databases"
slug: "azure-cosmos-db-flaw-could-have-exposed-all-databases"
author: "NewsBot (Validated by Federico Sella)"
description: "Una vulnerabilità corretta di Azure Cosmos DB consentiva l'escape dalla sandbox e l'accesso ai database tra tenant, scoperta da Wiz come CosmosEscape."
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

Una vulnerabilità corretta di Azure Cosmos DB consentiva l'escape dalla sandbox e l'accesso ai database tra tenant, scoperta da Wiz come CosmosEscape.

{{< cyber-report severity="High" source="The Hacker News" target="Azure Cosmos DB" >}}

Una vulnerabilità ora corretta in Azure Cosmos DB avrebbe potuto consentire a un attaccante di uscire dalla sandbox delle query Gremlin del servizio e ottenere accesso completo in lettura e scrittura ai database di altri tenant. La falla è stata scoperta dalla società di sicurezza Wiz, che ha soprannominato la catena di exploit 'CosmosEscape'.

{{< ad-banner >}}

La catena di attacco iniziava con una query appositamente predisposta contro un database Gremlin controllato dall'attaccante. Da lì, l'attaccante poteva ottenere l'esecuzione di codice sull'infrastruttura sottostante, compromettendo potenzialmente l'isolamento tra i tenant.

Sebbene Microsoft abbia corretto il problema, l'incidente sottolinea l'importanza critica dell'isolamento dei tenant nei servizi di database cloud. Le organizzazioni che utilizzano Azure Cosmos DB dovrebbero rivedere le proprie configurazioni di sicurezza e monitorare eventuali attività insolite.

{{< netrunner-insight >}}

Per gli analisti SOC, questo evidenzia la necessità di monitorare query Gremlin anomale e modelli di accesso ai database insoliti. I team DevSecOps dovrebbero garantire che i servizi di database cloud siano configurati con il principio del privilegio minimo e che i meccanismi di sandboxing siano regolarmente auditati. Anche se questo è stato corretto, vulnerabilità simili potrebbero esistere in altri servizi gestiti, quindi la caccia alle minacce proattiva è essenziale.

{{< /netrunner-insight >}}

---

**[Leggi l'articolo completo su The Hacker News ›](https://thehackernews.com/2026/07/azure-cosmos-db-flaw-exposed-platform.html)**
