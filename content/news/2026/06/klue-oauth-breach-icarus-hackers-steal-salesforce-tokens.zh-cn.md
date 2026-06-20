---
title: "Klue OAuth 泄露：Icarus 黑客窃取 Salesforce 令牌"
date: "2026-06-20T09:59:52Z"
original_date: "2026-06-19T22:31:04"
lang: "zh-cn"
translationKey: "klue-oauth-breach-icarus-hackers-steal-salesforce-tokens"
author: "NewsBot (Validated by Federico Sella)"
description: "Klue 确认 OAuth 令牌被盗，影响 Salesforce 集成；Icarus 勒索组织声称负责，受害者名单不断扩大。"
original_url: "https://www.bleepingcomputer.com/news/security/klue-oauth-breach-victim-list-grows-as-icarus-hackers-claim-attack/"
source: "BleepingComputer"
severity: "High"
target: "Klue 市场情报平台"
cve: null
cvss: null
kev: null
tags: ["news", "cybersecurity"]
news-categories: ["cybersecurity"]
layout: "news"
draft: false
---

Klue 确认 OAuth 令牌被盗，影响 Salesforce 集成；Icarus 勒索组织声称负责，受害者名单不断扩大。

{{< cyber-report severity="High" source="BleepingComputer" target="Klue 市场情报平台" >}}

市场情报平台 Klue 已确认发生安全事件，威胁行为者窃取了用于连接客户 Salesforce 环境的 OAuth 令牌。此次泄露由新出现的 'Icarus' 勒索组织声称负责，导致受影响受害者名单不断扩大。

{{< ad-banner >}}

被盗的 OAuth 令牌可能允许攻击者无需进一步身份验证即可访问 Salesforce 数据，对 Klue 客户构成重大风险。该事件凸显了 OAuth 令牌暴露的危险性以及健全令牌生命周期管理的必要性。

随着 Icarus 组织公开声称发动了此次攻击，使用 Klue Salesforce 集成的组织应立即撤销并轮换所有相关的 OAuth 令牌，并监控未经授权的访问。泄露的全部范围仍在调查中。

{{< netrunner-insight >}}

此事件强调了将 OAuth 令牌作为敏感凭证进行保护的关键重要性。SOC 分析师应优先监控异常的 Salesforce API 调用，并强制执行令牌过期策略。DevSecOps 团队必须实施严格的令牌范围和轮换机制，以在发生泄露时限制爆炸半径。

{{< /netrunner-insight >}}

---

**[在 BleepingComputer 上阅读全文 ›](https://www.bleepingcomputer.com/news/security/klue-oauth-breach-victim-list-grows-as-icarus-hackers-claim-attack/)**
