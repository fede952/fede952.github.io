---
title: "ABB B&R Automation Studio 漏洞使工业控制系统面临远程代码执行风险"
date: "2026-05-23T09:00:47Z"
original_date: "2026-05-21T12:00:00"
lang: "zh-cn"
translationKey: "abb-b-r-automation-studio-flaws-expose-ics-to-remote-code-execution"
author: "NewsBot (Validated by Federico Sella)"
description: "CISA 警告 ABB B&R Automation Studio 存在 25 个漏洞，其中包括 CVSS 9.8 的关键漏洞，可能导致未授权访问和远程代码执行。"
original_url: "https://www.cisa.gov/news-events/ics-advisories/icsa-26-141-03"
source: "CISA"
severity: "Critical"
target: "ABB B&R Automation Studio"
cve: "CVE-2025-6965"
cvss: 9.8
kev: null
tags: ["news", "cybersecurity"]
news-categories: ["cybersecurity"]
layout: "news"
draft: false
---

CISA 警告 ABB B&R Automation Studio 存在 25 个漏洞，其中包括 CVSS 9.8 的关键漏洞，可能导致未授权访问和远程代码执行。

{{< cyber-report severity="Critical" source="CISA" target="ABB B&R Automation Studio" cve="CVE-2025-6965" cvss="9.8" >}}

CISA 发布了一份公告，详细说明了 ABB B&R Automation Studio 中的多个漏洞，影响 6.5 之前版本及 6.5 版本。该公告列出了 25 个 CVE，包括 CVE-2025-6965、CVE-2025-3277 和 CVE-2023-7104 等。这些漏洞源于过时的第三方组件，包括基于堆的缓冲区溢出、越界写入、释放后使用以及输入验证不当等问题。

{{< ad-banner >}}

虽然 ABB 报告在测试期间未观察到利用行为，但这些漏洞可能为未授权访问、数据泄露或远程代码执行提供攻击途径。最严重的 CVE 的 CVSS v3 评分为 9.8，表明其严重性为关键。受影响的产品用于工业自动化和控制系统，使其成为威胁行为者的有吸引力的目标。

ABB 已发布更新，替换了过时的第三方组件。使用 B&R Automation Studio 的组织应立即应用更新。鉴于这些漏洞的关键性质以及远程利用的可能性，资产所有者应优先进行修补，并监控任何受损迹象。

{{< netrunner-insight >}}

对于 SOC 分析师和 DevSecOps 工程师而言，此公告强调了 ICS 软件中第三方依赖的风险。CVE 数量之多（25 个）表明组件管理存在系统性问题。优先清查 B&R Automation Studio 实例并应用供应商更新。此外，对 ICS 网络进行分段以限制暴露，并实施监控以检测可能表明利用尝试的异常行为。

{{< /netrunner-insight >}}

---

**[在 CISA 上阅读全文 ›](https://www.cisa.gov/news-events/ics-advisories/icsa-26-141-03)**
