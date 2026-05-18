---
title: "MiniPlasma Windows 0-Day 漏洞使完全修补的系统面临SYSTEM权限提升风险"
date: "2026-05-18T11:01:35Z"
original_date: "2026-05-18T08:57:34"
lang: "zh-cn"
translationKey: "miniplasma-windows-0-day-enables-system-privilege-escalation-on-fully-patched-systems"
author: "NewsBot (Validated by Federico Sella)"
description: "安全研究员 Chaotic Eclipse 发布了 MiniPlasma 的概念验证代码，这是 Windows Cloud Files 微型筛选器驱动程序 (cldflt.sys) 中的一个零日漏洞，可在完全修补的系统上授予 SYSTEM 权限。"
original_url: "https://thehackernews.com/2026/05/miniplasma-windows-0-day-enables-system.html"
source: "The Hacker News"
severity: "High"
target: "Windows Cloud Files 微型筛选器驱动程序 (cldflt.sys)"
cve: null
cvss: null
kev: null
tags: ["news", "cybersecurity"]
news-categories: ["cybersecurity"]
layout: "news"
draft: false
---

安全研究员 Chaotic Eclipse 发布了 MiniPlasma 的概念验证代码，这是 Windows Cloud Files 微型筛选器驱动程序 (cldflt.sys) 中的一个零日漏洞，可在完全修补的系统上授予 SYSTEM 权限。

{{< cyber-report severity="High" source="The Hacker News" target="Windows Cloud Files 微型筛选器驱动程序 (cldflt.sys)" >}}

安全研究员 Chaotic Eclipse（此前披露了 Windows 漏洞 YellowKey 和 GreenPlasma）发布了一个 Windows 权限提升零日漏洞的概念验证代码，该漏洞允许攻击者在完全修补的 Windows 系统上获得 SYSTEM 权限。该漏洞代号为 MiniPlasma，影响 "cldflt.sys"，即 Windows Cloud Files 微型筛选器驱动程序。

{{< ad-banner >}}

该漏洞允许具有有限用户访问权限的攻击者将权限提升至 SYSTEM，可能导致系统完全沦陷。作为一个零日漏洞，目前尚无官方补丁，如果概念验证代码被武器化，完全修补的系统将面临被利用的风险。

组织应监控 cldflt.sys 驱动程序的异常行为，并考虑采取额外的加固措施，例如限制对 Cloud Files 功能的访问，或在补丁发布前应用临时缓解措施。

{{< netrunner-insight >}}

SOC 分析师应优先监控针对 cldflt.sys 的利用尝试，因为概念验证代码降低了攻击者的门槛。DevSecOps 团队应审查其 Windows 镜像加固，并考虑在不需要时禁用 Cloud Files 微型筛选器驱动程序，同时等待微软的官方修复。

{{< /netrunner-insight >}}

---

**[在 The Hacker News 上阅读全文 ›](https://thehackernews.com/2026/05/miniplasma-windows-0-day-enables-system.html)**
