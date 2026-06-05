---
title: "日立能源ITT600 Explorer存在libexpat漏洞可致DoS攻击"
date: "2026-06-05T10:44:09Z"
original_date: "2026-06-04T12:00:00"
lang: "zh-cn"
translationKey: "hitachi-energy-itt600-explorer-vulnerable-to-dos-via-libexpat-flaws"
author: "NewsBot (Validated by Federico Sella)"
description: "CISA警告日立能源ITT600 Explorer中存在两个漏洞，可能导致拒绝服务攻击。影响2.1 SP6之前的版本。"
original_url: "https://www.cisa.gov/news-events/ics-advisories/icsa-26-155-02"
source: "CISA"
severity: "High"
target: "Hitachi Energy ITT600 Explorer"
cve: "CVE-2024-8176"
cvss: 7.5
kev: null
tags: ["news", "cybersecurity"]
news-categories: ["cybersecurity"]
layout: "news"
draft: false
---

CISA警告日立能源ITT600 Explorer中存在两个漏洞，可能导致拒绝服务攻击。影响2.1 SP6之前的版本。

{{< cyber-report severity="High" source="CISA" target="Hitachi Energy ITT600 Explorer" cve="CVE-2024-8176" cvss="7.5" >}}

日立能源已披露其ITT600 Explorer产品中的漏洞，具体影响2.1 SP6之前的版本。这些漏洞被标识为CVE-2024-8176和CVE-2025-59375，涉及无限制递归以及资源分配无限制或节流。这些问题可被利用导致拒绝服务（DoS）状态。

{{< ad-banner >}}

漏洞存在于IEC61850功能所使用的libexpat库中。具有本地访问权限的攻击者可发送特制的IEC61850消息触发堆栈溢出，除DoS外还可能导致内存损坏。重要的是，仅ITT600 Explorer产品受影响；IEC 61850系统端点不受影响。

CISA建议立即采取行动应用缓解措施或更新。该产品在全球能源行业部署，利用可能破坏关键基础设施运营。使用受影响版本的组织应优先修补，并查阅公告了解详细修复步骤。

{{< netrunner-insight >}}

对于SOC分析师，监控异常的IEC61850流量模式，这可能表明利用尝试。DevSecOps团队应优先将ITT600 Explorer更新至2.1 SP6或更高版本，并考虑网络分段以限制对该工具的本地访问。鉴于CVSS评分为7.5以及潜在的内存损坏，将此视为高优先级补丁。

{{< /netrunner-insight >}}

---

**[在 CISA 上阅读全文 ›](https://www.cisa.gov/news-events/ics-advisories/icsa-26-155-02)**
