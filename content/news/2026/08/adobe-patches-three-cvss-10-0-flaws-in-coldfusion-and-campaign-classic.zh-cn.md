---
title: "Adobe 修补 ColdFusion 和 Campaign Classic 中的三个 CVSS 10.0 漏洞"
date: "2026-08-13T08:18:27Z"
original_date: "2026-08-12T11:13:03"
lang: "zh-cn"
translationKey: "adobe-patches-three-cvss-10-0-flaws-in-coldfusion-and-campaign-classic"
slug: "adobe-patches-three-cvss-10-0-flaws-in-coldfusion-and-campaign-classic"
author: "NewsBot (Validated by Federico Sella)"
description: "Adobe 发布针对 ColdFusion、Commerce 和 Campaign Classic 的关键更新，解决了 CVSS 10.0 严重级别的命令注入和权限提升漏洞。"
original_url: "https://thehackernews.com/2026/08/adobe-patches-three-cvss-100-coldfusion.html"
source: "The Hacker News"
severity: "Critical"
target: "Adobe ColdFusion、Commerce、Campaign Classic"
cve: "CVE-2026-48362"
cvss: 10.0
kev: null
tags: ["news", "cybersecurity"]
news-categories: ["cybersecurity"]
layout: "news"
draft: false
---

Adobe 发布针对 ColdFusion、Commerce 和 Campaign Classic 的关键更新，解决了 CVSS 10.0 严重级别的命令注入和权限提升漏洞。

{{< cyber-report severity="Critical" source="The Hacker News" target="Adobe ColdFusion、Commerce、Campaign Classic" cve="CVE-2026-48362" cvss="10.0" >}}

Adobe 已发布紧急安全更新，以解决 ColdFusion、Commerce 和 Campaign Classic 中的多个关键漏洞。其中最严重的是 CVE-2026-48362，这是一个 CVSS 10.0 级的操作系统命令注入漏洞，存在于 ColdFusion 中，可能允许攻击者在底层系统上执行任意代码。

{{< ad-banner >}}

除了命令注入漏洞外，这些更新还解决了其他可能导致权限提升的关键问题。成功利用这些漏洞可能使攻击者完全控制受影响的服务器，进而可能导致数据泄露、横向移动或对基础设施的进一步破坏。

鉴于这些漏洞的 CVSS 评分最高，且这些产品在企业环境中具有关键性，强烈建议立即进行修补。组织还应审查其安全监控，以查找与这些漏洞相关的入侵指标。

{{< netrunner-insight >}}

CVSS 10.0 的评分意味着这些漏洞的严重性已达到最高级别——应将其视为活跃的利用场景。立即优先修补 ColdFusion 和 Campaign Classic 服务器，并检查是否有任何利用后活动的迹象。此外，如果可能，考虑将这些服务与互联网隔离，并审查日志中是否有异常的命令执行模式。

{{< /netrunner-insight >}}

---

**[在 The Hacker News 上阅读全文 ›](https://thehackernews.com/2026/08/adobe-patches-three-cvss-100-coldfusion.html)**
