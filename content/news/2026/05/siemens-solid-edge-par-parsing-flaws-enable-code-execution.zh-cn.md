---
title: "西门子Solid Edge PAR解析漏洞可致代码执行"
date: "2026-05-16T08:48:36Z"
original_date: "2026-05-14T12:00:00"
lang: "zh-cn"
translationKey: "siemens-solid-edge-par-parsing-flaws-enable-code-execution"
author: "NewsBot (Validated by Federico Sella)"
description: "西门子Solid Edge SE2026中的两个文件解析漏洞允许攻击者通过特制的PAR文件执行任意代码。请更新至V226.0 Update 5。"
original_url: "https://www.cisa.gov/news-events/ics-advisories/icsa-26-134-03"
source: "CISA"
severity: "High"
target: "Siemens Solid Edge SE2026"
cve: "CVE-2026-44411"
cvss: 7.8
kev: null
tags: ["news", "cybersecurity"]
news-categories: ["cybersecurity"]
layout: "news"
draft: false
---

西门子Solid Edge SE2026中的两个文件解析漏洞允许攻击者通过特制的PAR文件执行任意代码。请更新至V226.0 Update 5。

{{< cyber-report severity="High" source="CISA" target="Siemens Solid Edge SE2026" cve="CVE-2026-44411" cvss="7.8" >}}

西门子Solid Edge SE2026（Update 5之前版本）受两个文件解析漏洞影响，当应用程序读取特制的PAR文件时可能触发这些漏洞。这些缺陷包括未初始化指针访问（CVE-2026-44411）和基于栈的缓冲区溢出（CVE-2026-44412），两者都可能允许攻击者在当前进程上下文中使应用程序崩溃或执行任意代码。

{{< ad-banner >}}

这些漏洞的CVSS v3.1基础评分为7.8（高），向量为AV:L/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H，表明需要本地访问、低复杂度、无需权限、需要用户交互，且对机密性、完整性和可用性影响高。西门子已发布V226.0 Update 5版本以解决这些问题，并建议用户立即更新。

鉴于全球关键制造行业的部署情况，使用Solid Edge的组织应优先进行修补。这些漏洞需要用户交互（打开恶意PAR文件），因此建议将用户安全意识培训作为补偿控制措施。

{{< netrunner-insight >}}

对于SOC分析师，请监控Solid Edge进程中异常的PAR文件处理或崩溃。DevSecOps工程师应实施应用程序白名单并限制文件类型以减少攻击面。由于这些是本地、依赖用户交互的漏洞，钓鱼模拟和针对可疑文件打开的端点检测规则是关键缓解措施。

{{< /netrunner-insight >}}

---

**[在 CISA 上阅读全文 ›](https://www.cisa.gov/news-events/ics-advisories/icsa-26-134-03)**
