---
title: "CISA警告：Rockwell FactoryTalk Analytics PavilionX存在严重认证绕过漏洞"
date: "2026-06-18T11:06:01Z"
original_date: "2026-06-16T12:00:00"
lang: "zh-cn"
translationKey: "cisa-warns-of-critical-auth-bypass-in-rockwell-factorytalk-analytics-pavilionx"
author: "NewsBot (Validated by Federico Sella)"
description: "CISA就影响Rockwell Automation FactoryTalk Analytics PavilionX <7.01的CVE-2025-14272发出警报，该漏洞允许在关键制造环境中进行未授权的特权操作。"
original_url: "https://www.cisa.gov/news-events/ics-advisories/icsa-26-167-01"
source: "CISA"
severity: "High"
target: "Rockwell FactoryTalk Analytics PavilionX"
cve: "CVE-2025-14272"
cvss: null
kev: null
tags: ["news", "cybersecurity"]
news-categories: ["cybersecurity"]
layout: "news"
draft: false
---

CISA就影响Rockwell Automation FactoryTalk Analytics PavilionX <7.01的CVE-2025-14272发出警报，该漏洞允许在关键制造环境中进行未授权的特权操作。

{{< cyber-report severity="High" source="CISA" target="Rockwell FactoryTalk Analytics PavilionX" cve="CVE-2025-14272" >}}

CISA发布了一份公告（ICSA-26-167-01），涉及Rockwell Automation FactoryTalk Analytics PavilionX中的一个缺失授权漏洞。该漏洞编号为CVE-2025-14272，影响7.01之前的版本，允许未授权攻击者执行特权操作，如用户和角色管理。

{{< ad-banner >}}

该漏洞源于API端点中授权执行不当。成功利用可能导致对受影响系统的完全管理控制。Rockwell Automation已发布7.01版本来修复此问题，用户应立即升级。

鉴于该产品在全球关键制造领域的部署，运营中断或数据泄露的风险很大。各组织应优先进行修补，并审查访问控制以减轻潜在利用风险。

{{< netrunner-insight >}}

这是一个典型的授权绕过漏洞，应作为高优先级补丁处理。SOC分析师应监控PavilionX环境中的异常API调用或权限提升。DevSecOps团队必须确保部署7.01版本，并通过网络分段限制这些端点的暴露。

{{< /netrunner-insight >}}

---

**[在 CISA 上阅读全文 ›](https://www.cisa.gov/news-events/ics-advisories/icsa-26-167-01)**
