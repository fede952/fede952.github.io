---
title: "微软2026年4月补丁星期二：167个漏洞，SharePoint零日漏洞，BlueHammer"
date: "2026-05-11T10:37:48Z"
original_date: "2026-04-14T21:47:59"
lang: "zh-cn"
translationKey: "microsoft-patch-tuesday-april-2026-167-flaws-sharepoint-zero-day-bluehammer"
author: "NewsBot (Validated by Federico Sella)"
description: "微软修复了167个漏洞，包括一个SharePoint零日漏洞和一个公开披露的Windows Defender缺陷（BlueHammer）。谷歌Chrome和Adobe Reader也修补了正在被积极利用的漏洞。"
original_url: "https://krebsonsecurity.com/2026/04/patch-tuesday-april-2026-edition/"
source: "Krebs on Security"
severity: "Critical"
target: "Microsoft Windows, SharePoint, Windows Defender, Chrome, Adobe Reader"
cve: null
cvss: null
kev: null
tags: ["news", "cybersecurity"]
news-categories: ["cybersecurity"]
layout: "news"
draft: false
---

微软修复了167个漏洞，包括一个SharePoint零日漏洞和一个公开披露的Windows Defender缺陷（BlueHammer）。谷歌Chrome和Adobe Reader也修补了正在被积极利用的漏洞。

{{< cyber-report severity="Critical" source="Krebs on Security" target="Microsoft Windows, SharePoint, Windows Defender, Chrome, Adobe Reader" >}}

微软2026年4月补丁星期二解决了Windows及相关软件中多达167个安全漏洞。其中最严重的是SharePoint Server中的一个零日漏洞，可能导致远程代码执行，但报告中未提供CVE标识符。此外，Windows Defender中一个名为“BlueHammer”的公开披露弱点已被修复。

{{< ad-banner >}}

另外，谷歌Chrome修补了2026年的第四个零日漏洞，延续了浏览器频繁更新的趋势。Adobe Reader也收到了紧急更新，以修复一个正在被积极利用、可能导致远程代码执行的漏洞。鉴于这些漏洞已被积极利用，各组织应优先进行更新。

本月补丁数量庞大，凸显了健全补丁管理流程的重要性。安全团队应将SharePoint零日漏洞和Windows Defender问题作为当务之急，同时确保整个企业范围内的Chrome和Adobe Reader都已更新。

{{< netrunner-insight >}}

对于SOC分析师，优先修补SharePoint零日漏洞和BlueHammer Windows Defender缺陷，因为它们要么正在被积极利用，要么已公开。DevSecOps团队应将此更新集成到CI/CD管道中，并验证端点保护工具不会因Defender修复而中断。Chrome和Adobe Reader的补丁也因其被积极利用的状态而需要紧急关注。

{{< /netrunner-insight >}}

---

**[在 Krebs on Security 上阅读全文 ›](https://krebsonsecurity.com/2026/04/patch-tuesday-april-2026-edition/)**
