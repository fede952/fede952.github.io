---
title: "CISA警告：罗克韦尔自动化CompactLogix控制器存在拒绝服务漏洞"
date: "2026-06-17T11:46:16Z"
original_date: "2026-06-16T12:00:00"
lang: "zh-cn"
translationKey: "cisa-warns-of-dos-vulnerabilities-in-rockwell-automation-compactlogix-controllers"
author: "NewsBot (Validated by Federico Sella)"
description: "罗克韦尔自动化CompactLogix 5370控制器的多个漏洞可能导致拒绝服务攻击，其中CVE-2025-11694是漏洞之一。"
original_url: "https://www.cisa.gov/news-events/ics-advisories/icsa-26-167-04"
source: "CISA"
severity: "High"
target: "罗克韦尔自动化CompactLogix 5370控制器"
cve: "CVE-2025-11694"
cvss: 7.5
kev: null
tags: ["news", "cybersecurity"]
news-categories: ["cybersecurity"]
layout: "news"
draft: false
---

罗克韦尔自动化CompactLogix 5370控制器的多个漏洞可能导致拒绝服务攻击，其中CVE-2025-11694是漏洞之一。

{{< cyber-report severity="High" source="CISA" target="罗克韦尔自动化CompactLogix 5370控制器" cve="CVE-2025-11694" cvss="7.5" >}}

CISA发布了一份安全公告（ICSA-26-167-04），详细说明了罗克韦尔自动化CompactLogix 5370控制器（L1、L2、L3）中的漏洞。这些漏洞包括完整性校验值验证不当以及敏感系统信息暴露，可能允许攻击者造成拒绝服务条件。该公告影响V38.011之前的版本。

{{< ad-banner >}}

最值得注意的漏洞CVE-2025-11694涉及CIP协议中序列号和源IP地址验证缺失。攻击者可以利用Web界面上暴露的连接ID执行拒绝服务攻击，导致轻微故障。该漏洞的CVSS v3评分为7.5。

罗克韦尔自动化建议更新至V38.011版本以修复这些问题。受影响的产品在全球关键制造领域部署。各组织应优先修补这些控制器，以减轻潜在的业务中断风险。

{{< netrunner-insight >}}

对于SOC分析师，请监控针对CompactLogix控制器的异常CIP流量模式或重复连接尝试。DevSecOps工程师应确保Web界面不暴露于不可信网络，并立即应用固件更新至V38.011。这是一个简单的DoS向量，通过适当的网络分段和补丁管理即可缓解。

{{< /netrunner-insight >}}

---

**[在 CISA 上阅读全文 ›](https://www.cisa.gov/news-events/ics-advisories/icsa-26-167-04)**
