---
title: "Salesforce攻击范围扩大：Icarus通过Klue泄露窃取的数据"
date: "2026-06-24T10:22:11Z"
original_date: "2026-06-23T20:44:09"
lang: "zh-cn"
translationKey: "salesforce-attacks-widen-as-icarus-leaks-stolen-data-via-klue-breach"
author: "NewsBot (Validated by Federico Sella)"
description: "攻击者利用Klue的OAuth令牌访问Salesforce实例；随着Icarus泄露窃取的数据，更多受害者浮出水面。"
original_url: "https://www.darkreading.com/cyberattacks-data-breaches/scope-salesforce-attacks-expands-icarus-leaks-data"
source: "Dark Reading"
severity: "High"
target: "通过Klue OAuth令牌访问的Salesforce实例"
cve: null
cvss: null
kev: null
tags: ["news", "cybersecurity"]
news-categories: ["cybersecurity"]
layout: "news"
draft: false
---

攻击者利用Klue的OAuth令牌访问Salesforce实例；随着Icarus泄露窃取的数据，更多受害者浮出水面。

{{< cyber-report severity="High" source="Dark Reading" target="通过Klue OAuth令牌访问的Salesforce实例" >}}

针对Salesforce的持续攻击范围扩大，被追踪为Icarus的威胁行为者泄露了从多个受害者窃取的数据。攻击者最初入侵了应用供应商Klue，并利用其OAuth令牌未经授权访问客户的Salesforce环境。

{{< ad-banner >}}

据Dark Reading报道，在最初披露后，新的受害者出现，表明攻击活动比之前理解的更为广泛。使用OAuth令牌使攻击者能够绕过传统身份验证控制，直接访问Salesforce数据，而不会触发典型警报。

使用与Klue等第三方供应商集成的Salesforce的组织被敦促审计OAuth令牌权限，并监控异常访问模式。Icarus组织已开始泄露窃取的数据，增加了受影响公司应对的紧迫性。

{{< netrunner-insight >}}

此次攻击凸显了SaaS生态系统中OAuth令牌滥用的风险。SOC分析师应优先监控来自集成第三方应用程序的异常API调用和令牌使用。DevSecOps团队必须强制执行严格的令牌生命周期管理，并实施即时权限以限制爆炸半径。

{{< /netrunner-insight >}}

---

**[在 Dark Reading 上阅读全文 ›](https://www.darkreading.com/cyberattacks-data-breaches/scope-salesforce-attacks-expands-icarus-leaks-data)**
