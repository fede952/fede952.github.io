---
title: "Azure Cosmos DB 漏洞可能暴露所有数据库"
date: "2026-07-31T09:37:51Z"
original_date: "2026-07-30T13:34:09"
lang: "zh-cn"
translationKey: "azure-cosmos-db-flaw-could-have-exposed-all-databases"
slug: "azure-cosmos-db-flaw-could-have-exposed-all-databases"
author: "NewsBot (Validated by Federico Sella)"
description: "一个已修补的 Azure Cosmos DB 漏洞允许沙箱逃逸和跨租户数据库访问，由 Wiz 发现并命名为 CosmosEscape。"
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

一个已修补的 Azure Cosmos DB 漏洞允许沙箱逃逸和跨租户数据库访问，由 Wiz 发现并命名为 CosmosEscape。

{{< cyber-report severity="High" source="The Hacker News" target="Azure Cosmos DB" >}}

一个现已修补的 Azure Cosmos DB 漏洞可能允许攻击者逃逸该服务的 Gremlin 查询沙箱，并获得跨客户租户数据库的完全读写访问权限。该漏洞由安全公司 Wiz 发现，其将利用链代号为“CosmosEscape”。

{{< ad-banner >}}

攻击链始于对攻击者控制的 Gremlin 数据库的精心构造的查询。从那里，攻击者可以在底层基础设施上实现代码执行，可能破坏租户之间的隔离。

尽管 Microsoft 已修补该问题，但此事件凸显了云数据库服务中租户隔离的关键重要性。使用 Azure Cosmos DB 的组织应审查其安全配置，并监控任何异常活动。

{{< netrunner-insight >}}

对于 SOC 分析师而言，这凸显了监控异常 Gremlin 查询和异常数据库访问模式的必要性。DevSecOps 团队应确保云数据库服务按照最小权限原则配置，并定期审计任何沙箱机制。尽管此漏洞已修补，但其他托管服务中可能存在类似缺陷，因此主动威胁狩猎至关重要。

{{< /netrunner-insight >}}

---

**[在 The Hacker News 上阅读全文 ›](https://thehackernews.com/2026/07/azure-cosmos-db-flaw-exposed-platform.html)**
