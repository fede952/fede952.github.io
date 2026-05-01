---
title: "CISA 警告 ABB AWIN 网关存在允许重启和数据泄露的漏洞"
date: "2026-05-01T08:55:30Z"
original_date: "2026-04-30T12:00:00"
lang: "zh-cn"
translationKey: "cisa-warns-of-abb-awin-gateway-flaws-allowing-reboot-data-leak"
author: "NewsBot (Validated by Federico Sella)"
description: "ABB AWIN 网关存在漏洞，攻击者可借此重启设备或提取系统配置。CISA 公告 ICSA-26-120-05 详细说明了 CVE-2025-13777 及修复措施。"
original_url: "https://www.cisa.gov/news-events/ics-advisories/icsa-26-120-05"
source: "CISA"
severity: "High"
target: "ABB AWIN 网关"
cve: "CVE-2025-13777"
cvss: 8.3
kev: null
tags: ["news", "cybersecurity"]
news-categories: ["cybersecurity"]
layout: "news"
draft: false
---

ABB AWIN 网关存在漏洞，攻击者可借此重启设备或提取系统配置。CISA 公告 ICSA-26-120-05 详细说明了 CVE-2025-13777 及修复措施。

{{< cyber-report severity="High" source="CISA" target="ABB AWIN 网关" cve="CVE-2025-13777" cvss="8.3" >}}

CISA 发布了公告 ICSA-26-120-05，详细说明了 ABB AWIN 网关中的多个漏洞。这些漏洞包括通过捕获重放实现的身份验证绕过以及关键功能缺少身份验证，可能允许未经身份验证的攻击者远程重启设备或查询敏感的系统配置数据。受影响的 AWIN 固件版本为 2.0-0、2.0-1、1.2-0 和 1.2-1，运行在 GW100 rev.2 和 GW120 硬件上。

{{< ad-banner >}}

最严重的问题被追踪为 CVE-2025-13777，它允许未经身份验证的查询泄露系统配置，包括敏感信息。该公告给出的 CVSS v3 基础评分为 8.3，属于高危级别。ABB 已发布 GW100 rev.2 的固件版本 2.1-0 以修复这些漏洞。使用受影响网关的组织应立即应用更新。

这些漏洞影响全球部署的关键制造业资产。由于无需身份验证即可远程利用，这些缺陷对运营技术环境构成重大风险。CISA 建议用户查阅完整公告并实施缓解措施，包括网络分段和限制对受影响设备的访问。

{{< netrunner-insight >}}

对于 SOC 分析师：监控 ABB 网关的未授权重启或异常查询，这些是低噪声的利用迹象。DevSecOps 团队应优先将固件修补至 2.1-0 版本，并实施严格的网络访问控制，因为这些漏洞无需身份验证即可远程利用。

{{< /netrunner-insight >}}

---

**[在 CISA 上阅读全文 ›](https://www.cisa.gov/news-events/ics-advisories/icsa-26-120-05)**
