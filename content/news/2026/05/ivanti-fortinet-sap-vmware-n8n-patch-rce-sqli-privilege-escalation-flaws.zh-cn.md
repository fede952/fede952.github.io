---
title: "Ivanti、Fortinet、SAP、VMware、n8n 修补 RCE、SQL 注入、权限提升漏洞"
date: "2026-05-19T10:36:29Z"
original_date: "2026-05-18T10:54:05"
lang: "zh-cn"
translationKey: "ivanti-fortinet-sap-vmware-n8n-patch-rce-sqli-privilege-escalation-flaws"
author: "NewsBot (Validated by Federico Sella)"
description: "多家厂商发布安全更新修复关键漏洞，包括 Ivanti Xtraction CVE-2026-8043（CVSS 9.6），该漏洞可能导致信息泄露或客户端攻击。"
original_url: "https://thehackernews.com/2026/05/ivanti-fortinet-sap-vmware-n8n-patch.html"
source: "The Hacker News"
severity: "Critical"
target: "Ivanti Xtraction"
cve: "CVE-2026-8043"
cvss: 9.6
kev: null
tags: ["news", "cybersecurity"]
news-categories: ["cybersecurity"]
layout: "news"
draft: false
---

多家厂商发布安全更新修复关键漏洞，包括 Ivanti Xtraction CVE-2026-8043（CVSS 9.6），该漏洞可能导致信息泄露或客户端攻击。

{{< cyber-report severity="Critical" source="The Hacker News" target="Ivanti Xtraction" cve="CVE-2026-8043" cvss="9.6" >}}

Ivanti、Fortinet、n8n、SAP 和 VMware 已发布安全补丁，修复了多个可能被利用进行认证绕过和任意代码执行的漏洞。其中最严重的漏洞是 Ivanti Xtraction 中的 CVE-2026-8043，CVSS 评分为 9.6，该漏洞允许外部控制文件名，从而导致信息泄露或客户端攻击。

{{< ad-banner >}}

其他厂商也修复了高危漏洞，包括 SQL 注入和权限提升漏洞。组织应优先修补这些漏洞，尤其是暴露在互联网上的系统，因为它们可能被串联利用以实现完全系统入侵。

虽然尚未报告主动利用案例，但广泛的攻击面和高 CVSS 评分值得安全团队立即关注。定期漏洞扫描和补丁管理对于降低风险至关重要。

{{< netrunner-insight >}}

SOC 分析师应优先修补 Ivanti Xtraction CVE-2026-8043，因其关键 CVSS 评分和潜在的客户端攻击风险。DevSecOps 团队必须确保所有受影响系统已更新，并监控任何利用迹象，因为外部控制文件名可能导致数据泄露或横向移动。

{{< /netrunner-insight >}}

---

**[在 The Hacker News 上阅读全文 ›](https://thehackernews.com/2026/05/ivanti-fortinet-sap-vmware-n8n-patch.html)**
