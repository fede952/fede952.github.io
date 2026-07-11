---
title: "Zimbra 严重 XSS 漏洞可通过精心构造的邮件执行代码"
date: "2026-07-11T08:44:58Z"
original_date: "2026-07-11T06:45:55"
lang: "zh-cn"
translationKey: "critical-zimbra-xss-flaw-enables-code-execution-via-crafted-emails"
slug: "critical-zimbra-xss-flaw-enables-code-execution-via-crafted-emails"
author: "NewsBot (Validated by Federico Sella)"
description: "Zimbra 敦促用户更新经典网页客户端中的一个严重存储型 XSS 漏洞，该漏洞允许通过特制邮件执行任意代码。"
original_url: "https://thehackernews.com/2026/07/critical-zimbra-flaw-could-let-crafted_0483473395.html"
source: "The Hacker News"
severity: "Critical"
target: "Zimbra 经典网页客户端"
cve: null
cvss: null
kev: null
tags: ["news", "cybersecurity"]
news-categories: ["cybersecurity"]
layout: "news"
draft: false
---

Zimbra 敦促用户更新经典网页客户端中的一个严重存储型 XSS 漏洞，该漏洞允许通过特制邮件执行任意代码。

{{< cyber-report severity="Critical" source="The Hacker News" target="Zimbra 经典网页客户端" >}}

Zimbra 披露了其经典网页客户端中的一个严重安全漏洞，攻击者可通过存储型跨站脚本（XSS）执行任意代码。该漏洞允许特制邮件在用户会话中运行恶意脚本，可能导致邮件客户端及相关数据完全沦陷。

{{< ad-banner >}}

该漏洞尚未分配 CVE 标识符，影响经典网页客户端组件。Zimbra 敦促所有客户立即应用可用更新以降低风险。目前尚未提供 CVSS 评分，但通过邮件投递执行代码的能力使其成为依赖 Zimbra 的组织的高优先级问题。

作为存储型 XSS 漏洞，攻击无需用户交互，只需打开恶意邮件。这增加了被利用的可能性，尤其是在邮件过滤可能无法检测到精心构造的载荷的环境中。管理员应优先进行补丁更新并审查邮件安全控制措施。

{{< netrunner-insight >}}

对于 SOC 分析师而言，这是一个典型的存储型 XSS，可绕过传统邮件过滤器。DevSecOps 团队应立即修补 Zimbra 经典网页客户端，并考虑部署带有 XSS 规则的 Web 应用防火墙。监控用户会话中的异常脚本执行作为检测信号。

{{< /netrunner-insight >}}

---

**[在 The Hacker News 上阅读全文 ›](https://thehackernews.com/2026/07/critical-zimbra-flaw-could-let-crafted_0483473395.html)**
