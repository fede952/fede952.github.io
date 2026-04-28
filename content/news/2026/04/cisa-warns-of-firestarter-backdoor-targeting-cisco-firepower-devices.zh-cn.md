---
title: "CISA 警告针对 Cisco Firepower 设备的 FIRESTARTER 后门"
date: "2026-04-23T12:00:00"
lang: "zh-cn"
translationKey: "cisa-warns-of-firestarter-backdoor-targeting-cisco-firepower-devices"
author: "NewsBot (Validated by Federico Sella)"
description: "CISA 和 NCSC 发出警报，APT 行为者利用 FIRESTARTER 后门在 Cisco ASA/FTD 设备上实现持久化。概述了紧急响应措施。"
original_url: "https://www.cisa.gov/news-events/analysis-reports/ar26-113a"
source: "CISA"
severity: "High"
target: "Cisco Firepower 和 Secure Firewall 设备"
cve: null
cvss: null
kev: null
tags: ["news", "cybersecurity"]
news-categories: ["cybersecurity"]
layout: "news"
draft: false
---

CISA 和 NCSC 发出警报，APT 行为者利用 FIRESTARTER 后门在 Cisco ASA/FTD 设备上实现持久化。概述了紧急响应措施。

{{< cyber-report severity="High" source="CISA" target="Cisco Firepower 和 Secure Firewall 设备" >}}

CISA 和英国 NCSC 发布了关于 FIRESTARTER 后门的恶意软件分析报告，该后门被高级持续性威胁（APT）行为者用于在运行 ASA 或 FTD 软件的可公开访问的 Cisco Firepower 和 Secure Firewall 设备上维持持久化。该分析基于从取证调查中获得的样本，CISA 已确认在运行 ASA 软件的 Cisco Firepower 设备上成功实现了野外植入。

{{< ad-banner >}}

该发布与 CISA 的紧急指令 25-03 一致，敦促美国 FCEB 机构收集并提交核心转储到 CISA 的恶意软件下一代平台，并立即通过 24/7 运营中心报告提交情况。建议各组织在 CISA 提供后续步骤之前不要采取额外行动。

虽然该恶意软件与 Cisco Firepower 和 Secure Firewall 设备都相关，但 CISA 仅在运行 ASA 的 Firepower 设备上观察到成功植入。报告强调需要保持警惕并主动搜寻入侵指标。

{{< netrunner-insight >}}

SOC 分析师应优先从 Cisco ASA/FTD 设备收集核心转储并提交给 CISA 进行分析。DevSecOps 团队必须确保 Cisco 设备已根据最佳实践进行修补和配置，并监控异常的持久化机制。此后门突显了保护网络边缘设备免受 APT 级别威胁的重要性。

{{< /netrunner-insight >}}

---

**[在 CISA 上阅读全文 ›](https://www.cisa.gov/news-events/analysis-reports/ar26-113a)**
