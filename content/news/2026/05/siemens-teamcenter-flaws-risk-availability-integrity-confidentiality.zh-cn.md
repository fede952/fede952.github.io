---
title: "西门子Teamcenter漏洞威胁可用性、完整性和机密性"
date: "2026-05-16T08:47:33Z"
original_date: "2026-05-14T12:00:00"
lang: "zh-cn"
translationKey: "siemens-teamcenter-flaws-risk-availability-integrity-confidentiality"
author: "NewsBot (Validated by Federico Sella)"
description: "西门子Teamcenter中的多个漏洞可能危及可用性、完整性和机密性。请立即更新到最新版本。"
original_url: "https://www.cisa.gov/news-events/ics-advisories/icsa-26-134-04"
source: "CISA"
severity: "High"
target: "Siemens Teamcenter"
cve: "CVE-2024-4367"
cvss: 7.5
kev: null
tags: ["news", "cybersecurity"]
news-categories: ["cybersecurity"]
layout: "news"
draft: false
---

西门子Teamcenter中的多个漏洞可能危及可用性、完整性和机密性。请立即更新到最新版本。

{{< cyber-report severity="High" source="CISA" target="Siemens Teamcenter" cve="CVE-2024-4367" cvss="7.5" >}}

西门子Teamcenter受到多个漏洞的影响，这些漏洞可能导致可用性、完整性和机密性受损。漏洞包括对异常或特殊情况检查不当、跨站脚本以及使用硬编码凭据。受影响的版本包括Teamcenter V2312、V2406、V2412、V2506和V2512。

{{< ad-banner >}}

CVE-2024-4367是在处理PDF.js中的字体时缺少类型检查，允许在PDF.js上下文中执行任意JavaScript。该漏洞影响Firefox和Thunderbird，但被列入西门子公告。西门子建议更新到最新版本的Teamcenter以缓解这些风险。

这些漏洞的CVSS v3基础评分为7.5，表明严重性高。关键制造业部门受到影响，部署范围遍及全球。组织应优先进行修补，并审查对这些漏洞的暴露情况。

{{< netrunner-insight >}}

SOC分析师应立即清查所有Teamcenter实例，并优先修补到最新版本。DevSecOps团队必须验证PDF.js组件已更新，并监控针对这些CVE的利用尝试。鉴于CVSS评分高且可能完全受损，请将此视为高优先级修复。

{{< /netrunner-insight >}}

---

**[在 CISA 上阅读全文 ›](https://www.cisa.gov/news-events/ics-advisories/icsa-26-134-04)**
