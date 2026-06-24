---
title: "LastPass确认因Klue供应链攻击导致数据泄露"
date: "2026-06-24T10:23:36Z"
original_date: "2026-06-23T13:58:25"
lang: "zh-cn"
translationKey: "lastpass-confirms-data-breach-via-klue-supply-chain-attack"
author: "NewsBot (Validated by Federico Sella)"
description: "LastPass披露，攻击者从第三方应用Klue窃取了OAuth令牌，从而访问了其Salesforce环境中的客户数据。"
original_url: "https://www.bleepingcomputer.com/news/security/lastpass-confirms-data-breach-in-klue-supply-chain-attack/"
source: "BleepingComputer"
severity: "High"
target: "LastPass Salesforce环境"
cve: null
cvss: null
kev: null
tags: ["news", "cybersecurity"]
news-categories: ["cybersecurity"]
layout: "news"
draft: false
---

LastPass披露，攻击者从第三方应用Klue窃取了OAuth令牌，从而访问了其Salesforce环境中的客户数据。

{{< cyber-report severity="High" source="BleepingComputer" target="LastPass Salesforce环境" >}}

LastPass已确认，在本月初的Klue供应链攻击中，黑客窃取了该公司的OAuth令牌后，访问了其Salesforce环境中的客户数据。此次泄露事件于2026年6月23日披露，凸显了第三方集成和令牌窃取的风险。

{{< ad-banner >}}

攻击者利用从第三方应用Klue窃取的受损OAuth令牌，未经授权访问了LastPass的Salesforce实例。这次供应链攻击使威胁行为者能够在不触发典型身份验证警报的情况下窃取客户数据。

LastPass正在通知受影响的客户，并已撤销受损的令牌。该公司还在审查其第三方访问策略，以防止类似事件发生。此次泄露事件强调了监控OAuth令牌使用情况以及对集成服务实施严格访问控制的重要性。

{{< netrunner-insight >}}

此次事件是通过OAuth令牌滥用实现供应链风险的典型案例。SOC分析师应优先监控异常的令牌使用情况，并实施令牌过期策略。DevSecOps团队必须对第三方集成强制执行最小权限访问，并考虑使用短期令牌以缩小爆炸半径。

{{< /netrunner-insight >}}

---

**[在 BleepingComputer 上阅读全文 ›](https://www.bleepingcomputer.com/news/security/lastpass-confirms-data-breach-in-klue-supply-chain-attack/)**
