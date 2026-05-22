---
title: "ABB Terra AC Wallbox 漏洞允许远程代码执行"
date: "2026-05-22T10:24:17Z"
original_date: "2026-05-21T12:00:00"
lang: "zh-cn"
translationKey: "abb-terra-ac-wallbox-vulnerabilities-allow-remote-code-execution"
author: "NewsBot (Validated by Federico Sella)"
description: "CISA 警告 ABB Terra AC Wallbox (JP) ≤1.8.33 存在堆和栈缓冲区溢出；更新至 1.8.36 以缓解 CVE-2025-10504、CVE-2025-12142、CVE-2025-12143。"
original_url: "https://www.cisa.gov/news-events/ics-advisories/icsa-26-141-05"
source: "CISA"
severity: "Medium"
target: "ABB Terra AC Wallbox (JP)"
cve: "CVE-2025-10504"
cvss: 6.1
kev: null
tags: ["news", "cybersecurity"]
news-categories: ["cybersecurity"]
layout: "news"
draft: false
---

CISA 警告 ABB Terra AC Wallbox (JP) ≤1.8.33 存在堆和栈缓冲区溢出；更新至 1.8.36 以缓解 CVE-2025-10504、CVE-2025-12142、CVE-2025-12143。

{{< cyber-report severity="Medium" source="CISA" target="ABB Terra AC Wallbox (JP)" cve="CVE-2025-10504" cvss="6.1" >}}

ABB 披露了影响其 Terra AC Wallbox (JP) 产品线的多个漏洞，具体涉及版本 1.8.33 及之前版本。这些缺陷包括基于堆的缓冲区溢出 (CVE-2025-10504)、未检查输入大小的缓冲区复制 (CVE-2025-12142) 以及基于栈的缓冲区溢出 (CVE-2025-12143)。成功利用这些漏洞可能允许攻击者破坏堆内存，从而可能导致远程控制设备以及对闪存进行未经授权的写入，进而改变固件行为。

{{< ad-banner >}}

这些漏洞的 CVSS v3 基础评分为 6.1，属于中等严重性。ABB 已发布固件版本 1.8.36 以解决这些问题。这些产品在全球能源领域部署，供应商建议尽早应用更新。

虽然尚未报告有活跃的利用行为，但远程代码执行和固件篡改的可能性使得这些漏洞对电动汽车充电基础设施的运营商至关重要。各组织应优先修补受影响的设备，尤其是那些暴露于不可信网络的设备。

{{< netrunner-insight >}}

对于 SOC 分析师，请监控发往 Terra AC Wallbox 设备的异常流量，特别是对闪存的意外写入操作。DevSecOps 工程师应在与充电器通信的任何自定义协议中强制执行严格的输入验证，并确保及时应用固件更新。鉴于 CVSS 评分为 6.1，将其视为中等优先级，但由于该设备在关键能源基础设施中的作用，其潜在影响较高。

{{< /netrunner-insight >}}

---

**[在 CISA 上阅读全文 ›](https://www.cisa.gov/news-events/ics-advisories/icsa-26-141-05)**
