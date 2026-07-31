---
title: "Azure Cosmos DB Flaw Could Have Exposed All Databases"
date: "2026-07-31T09:37:51Z"
original_date: "2026-07-30T13:34:09"
lang: "en"
translationKey: "azure-cosmos-db-flaw-could-have-exposed-all-databases"
slug: "azure-cosmos-db-flaw-could-have-exposed-all-databases"
author: "NewsBot (Validated by Federico Sella)"
description: "A patched Azure Cosmos DB vulnerability allowed sandbox escape and cross-tenant database access, discovered by Wiz as CosmosEscape."
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

A patched Azure Cosmos DB vulnerability allowed sandbox escape and cross-tenant database access, discovered by Wiz as CosmosEscape.

{{< cyber-report severity="High" source="The Hacker News" target="Azure Cosmos DB" >}}

A now-patched vulnerability in Azure Cosmos DB could have allowed an attacker to escape the service's Gremlin query sandbox and gain full read and write access to databases across customer tenants. The flaw was discovered by security firm Wiz, which codenamed the exploit chain 'CosmosEscape'.

{{< ad-banner >}}

The attack chain began with a crafted query against a Gremlin database controlled by the attacker. From there, the attacker could achieve code execution on the underlying infrastructure, potentially compromising the isolation between tenants.

While Microsoft has since patched the issue, the incident underscores the critical importance of tenant isolation in cloud database services. Organizations using Azure Cosmos DB should review their security configurations and monitor for any unusual activity.

{{< netrunner-insight >}}

For SOC analysts, this highlights the need to monitor for anomalous Gremlin queries and unusual database access patterns. DevSecOps teams should ensure that cloud database services are configured with the principle of least privilege and that any sandboxing mechanisms are regularly audited. Even though this is patched, similar flaws may exist in other managed services, so proactive threat hunting is essential.

{{< /netrunner-insight >}}

---

**[Read full article on The Hacker News ›](https://thehackernews.com/2026/07/azure-cosmos-db-flaw-exposed-platform.html)**
