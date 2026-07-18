---
title: "新的wp2shell WordPress核心漏洞允许未经身份验证的攻击者执行代码"
date: "2026-07-18T08:47:36Z"
original_date: "2026-07-17T21:20:10"
lang: "zh-cn"
translationKey: "new-wp2shell-wordpress-core-flaw-lets-unauthenticated-attackers-run-code"
slug: "new-wp2shell-wordpress-core-flaw-lets-unauthenticated-attackers-run-code"
author: "NewsBot (Validated by Federico Sella)"
description: "一个匿名的HTTP请求可以在WordPress网站上执行代码。该漏洞影响核心，因此即使是裸安装也可被利用。在修补之前，每个6.9和7.0版本的网站都处于风险之中。"
original_url: "https://thehackernews.com/2026/07/new-wp2shell-wordpress-core-flaw-lets.html"
source: "The Hacker News"
severity: "Critical"
target: "WordPress核心（版本6.9和7.0）"
cve: null
cvss: null
kev: null
tags: ["news", "cybersecurity"]
news-categories: ["cybersecurity"]
layout: "news"
draft: false
---

一个匿名的HTTP请求可以在WordPress网站上执行代码。该漏洞影响核心，因此即使是裸安装也可被利用。在修补之前，每个6.9和7.0版本的网站都处于风险之中。

{{< cyber-report severity="Critical" source="The Hacker News" target="WordPress核心（版本6.9和7.0）" >}}

在WordPress核心中发现了一个严重的未经身份验证的远程代码执行漏洞，影响版本6.9和7.0。该漏洞被称为wp2shell，允许攻击者通过发送特制的HTTP请求在目标网站上执行任意代码。值得注意的是，该漏洞存在于核心软件中，这意味着即使是全新安装且没有插件的WordPress也可被利用。

{{< ad-banner >}}

完整的技术细节和有效的概念验证代码已经发布，同时为这两个底层漏洞分配了CVE标识符。还发现了一个持久对象缓存条件，这可能会使某些环境中的利用复杂化。在应用补丁之前，所有运行受影响版本的网站都被视为存在风险。

管理员应立即更新到最新的修补版本。鉴于利用的简便性和WordPress的广泛使用，该漏洞对网络安全构成了重大威胁。组织应优先进行修补，并审查其Web应用防火墙规则，以检测和阻止利用尝试。

{{< netrunner-insight >}}

这是一个教科书式的例子，说明了为什么核心软件必须加强防范未经身份验证的攻击。SOC分析师应立即扫描WordPress 6.9和7.0实例，并验证补丁状态。DevSecOps团队应将其视为实施运行时应用自我保护（RASP）并监控针对wp-admin或wp-includes的异常HTTP请求的提醒。

{{< /netrunner-insight >}}

---

**[在 The Hacker News 上阅读全文 ›](https://thehackernews.com/2026/07/new-wp2shell-wordpress-core-flaw-lets.html)**
