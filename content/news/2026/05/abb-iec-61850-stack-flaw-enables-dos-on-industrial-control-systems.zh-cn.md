---
title: "ABB IEC 61850 协议栈漏洞可致工业控制系统遭拒绝服务攻击"
date: "2026-05-01T09:03:14Z"
original_date: "2026-04-30T12:00:00"
lang: "zh-cn"
translationKey: "abb-iec-61850-stack-flaw-enables-dos-on-industrial-control-systems"
author: "NewsBot (Validated by Federico Sella)"
description: "CISA 警告称，ABB 的 IEC 61850 MMS 实现中存在一个私下报告的漏洞，影响 System 800xA 和 Symphony Plus 产品，可导致设备故障和拒绝服务。"
original_url: "https://www.cisa.gov/news-events/ics-advisories/icsa-26-120-01"
source: "CISA"
severity: "High"
target: "ABB System 800xA, Symphony Plus IEC 61850"
cve: null
cvss: null
kev: null
tags: ["news", "cybersecurity"]
news-categories: ["cybersecurity"]
layout: "news"
draft: false
---

CISA 警告称，ABB 的 IEC 61850 MMS 实现中存在一个私下报告的漏洞，影响 System 800xA 和 Symphony Plus 产品，可导致设备故障和拒绝服务。

{{< cyber-report severity="High" source="CISA" target="ABB System 800xA, Symphony Plus IEC 61850" >}}

CISA 发布了一份公告 (ICSA-26-120-01)，涉及 ABB 为 MMS 客户端应用程序实现的 IEC 61850 通信协议栈中的一个漏洞。该漏洞影响 System 800xA 和 Symphony Plus 产品线中的多个产品，包括 AC800M CI868、Symphony Plus SD 系列 CI850、PM 877 和 S+ Operations。利用该漏洞需要事先访问站点的 IEC 61850 网络。

{{< ad-banner >}}

成功利用会导致 PM 877、CI850 和 CI868 模块出现设备故障，需要手动重启。对于 S+ Operations 节点，攻击会使 IEC 61850 通信驱动程序崩溃，如果重复攻击，会导致拒绝服务状态。然而，整体节点的可用性和功能不受影响，GOOSE 协议通信也不受影响。System 800xA IEC61850 Connect 也不受此漏洞影响。

受影响的固件版本涵盖多个分支，包括 S+ Operations 直至 6.2.0006.0 以及各种 PM 877 版本。公告中未提供 CVE 标识符或 CVSS 评分。使用这些产品的组织应审查公告并应用缓解措施，例如网络分段和访问控制，以限制对 IEC 61850 网络的暴露。

{{< netrunner-insight >}}

此漏洞凸显了 OT 环境中网络分段的重要性。由于利用需要访问 IEC 61850 网络，因此将该网络与企业 IT 和互联网隔离至关重要。SOC 分析师应监控异常的 IEC 61850 流量，而 DevSecOps 工程师应优先进行修补，并考虑实施针对 MMS 协议异常的入侵检测。

{{< /netrunner-insight >}}

---

**[在 CISA 上阅读全文 ›](https://www.cisa.gov/news-events/ics-advisories/icsa-26-120-01)**
