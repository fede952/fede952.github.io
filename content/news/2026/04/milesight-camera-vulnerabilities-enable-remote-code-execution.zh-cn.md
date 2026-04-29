---
title: "Milesight摄像头漏洞可致远程代码执行"
date: "2026-04-29T07:21:59Z"
original_date: "2026-04-23T12:00:00"
lang: "zh-cn"
translationKey: "milesight-camera-vulnerabilities-enable-remote-code-execution"
author: "NewsBot (Validated by Federico Sella)"
description: "CISA警告称，多款Milesight摄像头型号存在严重漏洞（CVE-2026-28747等），可能导致设备崩溃或远程代码执行。"
original_url: "https://www.cisa.gov/news-events/ics-advisories/icsa-26-113-03"
source: "CISA"
severity: "Critical"
target: "Milesight IP摄像头"
cve: "CVE-2026-28747"
cvss: null
kev: null
tags: ["news", "cybersecurity"]
news-categories: ["cybersecurity"]
layout: "news"
draft: false
---

CISA警告称，多款Milesight摄像头型号存在严重漏洞（CVE-2026-28747等），可能导致设备崩溃或远程代码执行。

{{< cyber-report severity="Critical" source="CISA" target="Milesight IP摄像头" cve="CVE-2026-28747" >}}

CISA发布了一份安全公告（ICSA-26-113-03），详细说明了影响多款Milesight摄像头型号的多个漏洞。这些漏洞被标识为CVE-2026-28747、CVE-2026-27785、CVE-2026-32644、CVE-2026-32649和CVE-2026-20766，影响包括MS-Cxx63-PD、MS-Cxx64-xPD等多个产品系列的固件版本。成功利用这些漏洞可能导致攻击者使设备崩溃或实现远程代码执行。

{{< ad-banner >}}

受影响的型号涵盖多个系列，固件版本最高至51.7.0.77-r12、3x.8.0.3-r11、63.8.0.4-r3等。鉴于远程代码执行的严重性，这些漏洞对在监控或物联网部署中使用Milesight摄像头的组织构成重大风险。CISA建议用户应用可用补丁并遵循供应商指导以缓解风险。

尽管公告中未提供CVSS评分或主动利用的证据，但设备被入侵和网络渗透的可能性仍值得立即关注。安全团队应清查受影响的摄像头型号，将物联网设备与关键网络隔离，并优先更新固件。

{{< netrunner-insight >}}

对于SOC分析师，请监控来自摄像头子网的异常流量，并确保这些设备已隔离。DevSecOps工程师应加快所有Milesight摄像头的补丁更新，因为边缘设备中的远程代码执行漏洞常成为横向移动的入口点。在供应商补丁得到验证之前，请将这些CVE视为严重级别。

{{< /netrunner-insight >}}

---

**[在 CISA 上阅读全文 ›](https://www.cisa.gov/news-events/ics-advisories/icsa-26-113-03)**
