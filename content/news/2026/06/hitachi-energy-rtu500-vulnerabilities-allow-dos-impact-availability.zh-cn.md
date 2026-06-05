---
title: "日立能源RTU500漏洞可致拒绝服务，影响可用性"
date: "2026-06-05T10:46:09Z"
original_date: "2026-06-04T12:00:00"
lang: "zh-cn"
translationKey: "hitachi-energy-rtu500-vulnerabilities-allow-dos-impact-availability"
author: "NewsBot (Validated by Federico Sella)"
description: "CISA警告日立能源RTU500系列存在多个漏洞，包括空指针解引用和无限循环，CVSS评分7.8。列出了受影响版本。"
original_url: "https://www.cisa.gov/news-events/ics-advisories/icsa-26-155-04"
source: "CISA"
severity: "High"
target: "日立能源RTU500系列CMU固件"
cve: "CVE-2025-69421"
cvss: 7.8
kev: null
tags: ["news", "cybersecurity"]
news-categories: ["cybersecurity"]
layout: "news"
draft: false
---

CISA警告日立能源RTU500系列存在多个漏洞，包括空指针解引用和无限循环，CVSS评分7.8。列出了受影响版本。

{{< cyber-report severity="High" source="CISA" target="日立能源RTU500系列CMU固件" cve="CVE-2025-69421" cvss="7.8" >}}

日立能源披露了影响其RTU500系列CMU固件的多个漏洞。这些缺陷包括空指针解引用、整数溢出或回绕，以及无法到达退出条件的循环（无限循环），可能导致拒绝服务情况。利用主要影响产品可用性，并可能对机密性和完整性产生次要影响。

{{< ad-banner >}}

由CISA（ICSA-26-155-04）发布的公告列出了受影响的固件版本，范围从12.7.1到13.8.1。涉及多个CVE，包括CVE-2025-69421、CVE-2026-24515、CVE-2026-25210、CVE-2026-32776、CVE-2026-32777、CVE-2026-32778和CVE-2026-8479。这些漏洞的CVSS v3基础评分为7.8，表明严重性较高。

日立能源建议按照公告的修复指南立即采取行动。鉴于关键基础设施的背景，使用受影响RTU500版本的组织应优先进行修补，并实施网络分段以降低利用风险。

{{< netrunner-insight >}}

这些漏洞提醒我们，OT设备在补丁周期上往往滞后。SOC团队应监控发往RTU500单元的异常流量，并确保这些设备与不受信任的网络隔离。DevSecOps工程师应将固件扫描集成到CI/CD流水线中，以便在部署前捕获已知CVE。

{{< /netrunner-insight >}}

---

**[在 CISA 上阅读全文 ›](https://www.cisa.gov/news-events/ics-advisories/icsa-26-155-04)**
