---
title: "CISA 警告 ABB EIBPORT 漏洞可导致数据访问和配置更改"
date: "2026-05-29T10:43:33Z"
original_date: "2026-05-28T12:00:00"
lang: "zh-cn"
translationKey: "cisa-warns-of-abb-eibport-vulnerabilities-allowing-data-access-and-config-changes"
author: "NewsBot (Validated by Federico Sella)"
description: "ABB EIBPORT 设备存在跨站脚本攻击和会话 ID 窃取漏洞。固件更新至 3.9.2 版本可用。"
original_url: "https://www.cisa.gov/news-events/ics-advisories/icsa-26-148-03"
source: "CISA"
severity: "High"
target: "ABB EIBPORT 设备"
cve: "CVE-2021-22291"
cvss: null
kev: null
tags: ["news", "cybersecurity"]
news-categories: ["cybersecurity"]
layout: "news"
draft: false
---

ABB EIBPORT 设备存在跨站脚本攻击和会话 ID 窃取漏洞。固件更新至 3.9.2 版本可用。

{{< cyber-report severity="High" source="CISA" target="ABB EIBPORT 设备" cve="CVE-2021-22291" >}}

CISA 发布了一份公告（ICSA-26-148-03），详细说明了 ABB EIBPORT 设备中的多个漏洞，特别是 EIBPORT V3 KNX 和 EIBPORT V3 KNX GSM 型号。这些漏洞包括一个跨站脚本（XSS）缺陷（CWE-79）和一个会话 ID 窃取问题（CVE-2021-22291），可能允许攻击者访问设备上存储的敏感信息并更改其配置。

{{< ad-banner >}}

受影响的固件版本是 3.9.2 之前的版本。ABB 已发布固件更新以修复这些私下报告的漏洞。这些产品在全球范围内部署，涉及关键制造业和信息技术领域，供应商总部位于瑞士。

尽管公告中未提供 CVSS 评分，但对设备完整性和机密性的潜在影响要求及时修补。使用受影响 ABB EIBPORT 设备的组织应尽快应用固件更新，以降低被利用的风险。

{{< netrunner-insight >}}

对于 SOC 分析师，优先扫描运行固件低于 3.9.2 的 ABB EIBPORT 设备，并监控异常配置更改或会话异常。DevSecOps 团队应将此固件更新纳入其补丁管理流程，特别是考虑到该设备在楼宇自动化和关键基础设施中的作用。

{{< /netrunner-insight >}}

---

**[在 CISA 上阅读全文 ›](https://www.cisa.gov/news-events/ics-advisories/icsa-26-148-03)**
