---
title: "Subnet Solutions PowerSYSTEM Center 漏洞导致信息泄露与CRLF注入"
date: "2026-05-13T09:40:06Z"
original_date: "2026-05-12T12:00:00"
lang: "zh-cn"
translationKey: "subnet-solutions-powersystem-center-flaws-enable-info-leak-crlf-injection"
author: "NewsBot (Validated by Federico Sella)"
description: "CISA警告Subnet Solutions PowerSYSTEM Center存在多个漏洞，包括信息泄露和CRLF注入，影响2020至2026版本。"
original_url: "https://www.cisa.gov/news-events/ics-advisories/icsa-26-132-02"
source: "CISA"
severity: "High"
target: "Subnet Solutions PowerSYSTEM Center"
cve: "CVE-2026-35504"
cvss: 8.2
kev: null
tags: ["news", "cybersecurity"]
news-categories: ["cybersecurity"]
layout: "news"
draft: false
---

CISA警告Subnet Solutions PowerSYSTEM Center存在多个漏洞，包括信息泄露和CRLF注入，影响2020至2026版本。

{{< cyber-report severity="High" source="CISA" target="Subnet Solutions PowerSYSTEM Center" cve="CVE-2026-35504" cvss="8.2" >}}

CISA发布了一份公告（ICSA-26-132-02），详细说明了Subnet Solutions PowerSYSTEM Center中的多个漏洞，该平台用于关键制造业和能源领域。漏洞包括授权不当（CVE-2026-26289），允许权限受限的认证用户导出设备账户并暴露通常仅限于管理员访问的敏感信息。此外，CRLF注入漏洞（CVE-2026-35504、CVE-2026-33570、CVE-2026-35555）可能使攻击者注入恶意标头或响应。

{{< ad-banner >}}

受影响版本涵盖PowerSYSTEM Center 2020（5.8.x至5.28.x）、2024（6.0.x至6.1.x）和2026（7.0.x）。这些漏洞的CVSS v3基础评分为8.2，表明严重性较高。成功利用可能导致信息泄露以及潜在的会话操纵或HTTP响应拆分。

鉴于该产品在全球关键基础设施中的部署，各组织应优先进行修补。Subnet Solutions可能已发布更新；建议管理员查阅供应商的安全公告并应用最新补丁。在此之前，请限制对PowerSYSTEM Center的网络访问并监控异常活动。

{{< netrunner-insight >}}

对于SOC分析师，请监控认证日志中异常的设备账户导出行为——这是CVE-2026-26289被利用的明显迹象。DevSecOps团队应立即盘点PowerSYSTEM Center版本并应用补丁，因为CRLF注入向量（CVE-2026-35504等）可能与其他攻击链结合，危及会话完整性。鉴于CVSS 8.2评分和关键行业暴露，请将此视为高优先级修复。

{{< /netrunner-insight >}}

---

**[在 CISA 上阅读全文 ›](https://www.cisa.gov/news-events/ics-advisories/icsa-26-132-02)**
