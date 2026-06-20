---
title: "Klue OAuth 漏洞导致 Icarus 窃取 Salesforce 数据"
date: "2026-06-20T10:03:21Z"
original_date: "2026-06-18T14:19:50"
lang: "zh-cn"
translationKey: "klue-oauth-breach-enables-icarus-salesforce-data-theft"
author: "NewsBot (Validated by Federico Sella)"
description: "威胁行为者利用 Klue 的 OAuth 漏洞，从多个组织中窃取 Salesforce CRM 数据，并以此进行持续的勒索活动。"
original_url: "https://www.bleepingcomputer.com/news/security/klue-oauth-breach-linked-to-icarus-salesforce-data-theft-attacks/"
source: "BleepingComputer"
severity: "High"
target: "通过 OAuth 窃取 Salesforce CRM 数据"
cve: null
cvss: null
kev: null
tags: ["news", "cybersecurity"]
news-categories: ["cybersecurity"]
layout: "news"
draft: false
---

威胁行为者利用 Klue 的 OAuth 漏洞，从多个组织中窃取 Salesforce CRM 数据，并以此进行持续的勒索活动。

{{< cyber-report severity="High" source="BleepingComputer" target="通过 OAuth 窃取 Salesforce CRM 数据" >}}

市场情报平台 Klue 遭遇 OAuth 漏洞，导致名为 'Icarus' 的威胁行为者团体从多个组织中窃取 Salesforce CRM 数据。攻击者利用被攻陷的 OAuth 令牌访问并窃取敏感的客户关系管理数据，目前正利用这些数据进行勒索活动。

{{< ad-banner >}}

此次漏洞凸显了 OAuth 集成和第三方访问关键业务平台所带来的风险。建议使用 Klue 服务的组织审查其 OAuth 令牌策略，并监控对 Salesforce 实例的未授权访问。

Icarus 与一系列针对 Salesforce 环境的数据窃取攻击有关。该团体的惯用手法是利用薄弱的 OAuth 配置和令牌管理实践，以获得对 CRM 数据的持久访问。

{{< netrunner-insight >}}

此事件强调了严格的 OAuth 令牌生命周期管理和持续监控第三方集成的关键需求。SOC 分析师应优先审计 OAuth 授权，并对来自集成应用的异常数据访问模式实施异常检测。

{{< /netrunner-insight >}}

---

**[在 BleepingComputer 上阅读全文 ›](https://www.bleepingcomputer.com/news/security/klue-oauth-breach-linked-to-icarus-salesforce-data-theft-attacks/)**
