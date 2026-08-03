---
title: "JetBrains 警告 TeamCity 存在严重身份验证绕过漏洞，可导致远程代码执行"
date: "2026-08-03T10:38:49Z"
original_date: "2026-07-30T22:01:31"
lang: "zh-cn"
translationKey: "jetbrains-warns-of-critical-teamcity-auth-bypass-leading-to-rce"
slug: "jetbrains-warns-of-critical-teamcity-auth-bypass-leading-to-rce"
author: "NewsBot (Validated by Federico Sella)"
description: "JetBrains 警告 TeamCity On-Premises 存在严重身份验证绕过漏洞，可能允许远程代码执行。建议立即修补。"
original_url: "https://www.bleepingcomputer.com/news/security/jetbrains-warns-of-critical-teamcity-remote-code-execution-flaw/"
source: "BleepingComputer"
severity: "Critical"
target: "TeamCity On-Premises"
cve: null
cvss: null
kev: null
tags: ["news", "cybersecurity"]
news-categories: ["cybersecurity"]
layout: "news"
draft: false
---

JetBrains 警告 TeamCity On-Premises 存在严重身份验证绕过漏洞，可能允许远程代码执行。建议立即修补。

{{< cyber-report severity="Critical" source="BleepingComputer" target="TeamCity On-Premises" >}}

JetBrains 已发布警告，称 TeamCity On-Premises 存在严重身份验证绕过漏洞。该漏洞可能被未经身份验证的攻击者利用，在受影响的服务器上实现远程代码执行，对依赖 TeamCity 进行构建和持续集成管道的组织构成严重风险。

{{< ad-banner >}}

该漏洞尤其令人担忧，因为 TeamCity 服务器通常包含敏感的源代码、构建产物和凭据，使其成为攻击者的高价值目标。如果成功利用，可能导致服务器完全受损，如果服务器未适当隔离，还可能影响更广泛的基础设施。

使用 TeamCity On-Premises 的组织应立即优先应用供应商提供的安全更新。在应用补丁之前，建议限制对 TeamCity 服务器的网络访问，并监控任何可疑活动。

{{< netrunner-insight >}}

这是一个严重漏洞，应视为紧急情况。SOC 分析师应立即检查其组织是否使用 TeamCity On-Premises，并验证补丁状态。鉴于存在未经身份验证的 RCE 可能性，如果服务器暴露，应假设已被入侵，并进行彻底的取证审查。DevSecOps 团队还应考虑对构建服务器进行分段，并实施严格的访问控制以减轻爆炸半径。

{{< /netrunner-insight >}}

---

**[在 BleepingComputer 上阅读全文 ›](https://www.bleepingcomputer.com/news/security/jetbrains-warns-of-critical-teamcity-remote-code-execution-flaw/)**
