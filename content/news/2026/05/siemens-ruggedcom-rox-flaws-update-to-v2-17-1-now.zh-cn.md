---
title: "西门子Ruggedcom ROX漏洞：立即更新至v2.17.1"
date: "2026-05-15T09:41:40Z"
original_date: "2026-05-14T12:00:00"
lang: "zh-cn"
translationKey: "siemens-ruggedcom-rox-flaws-update-to-v2-17-1-now"
author: "NewsBot (Validated by Federico Sella)"
description: "CISA警告西门子Ruggedcom ROX v2.17.1之前版本存在多个第三方漏洞。列出了超过30个CVE，包括远程代码执行风险。建议立即更新。"
original_url: "https://www.cisa.gov/news-events/ics-advisories/icsa-26-134-16"
source: "CISA"
severity: "High"
target: "西门子Ruggedcom ROX设备"
cve: "CVE-2019-13103"
cvss: null
kev: null
tags: ["news", "cybersecurity"]
news-categories: ["cybersecurity"]
layout: "news"
draft: false
---

CISA警告西门子Ruggedcom ROX v2.17.1之前版本存在多个第三方漏洞。列出了超过30个CVE，包括远程代码执行风险。建议立即更新。

{{< cyber-report severity="High" source="CISA" target="西门子Ruggedcom ROX设备" cve="CVE-2019-13103" >}}

西门子Ruggedcom ROX 2.17.1之前版本包含多个第三方漏洞，如CISA公告ICSA-26-134-16所述。受影响产品包括RUGGEDCOM ROX MX5000、MX5000RE和RX1400系列。西门子已发布更新版本修复这些问题，并强烈建议升级至最新版本。

{{< ad-banner >}}

该公告列出了从2019年到2025年的超过30个CVE，包括CVE-2019-13103、CVE-2022-2347和CVE-2025-0395。虽然未提供具体CVSS评分，但漏洞的广度和年代表明攻击面很大。许多CVE与第三方组件相关，可能导致远程代码执行、拒绝服务或信息泄露。

使用受影响Ruggedcom ROX设备的组织应优先进行修补，尤其是当设备暴露于不可信网络时。鉴于这些产品的工业性质，未修补的系统可能被用于横向移动或破坏关键基础设施。

{{< netrunner-insight >}}

这是嵌入式系统中累积技术债务的典型案例。SOC分析师应清查所有Ruggedcom ROX实例并验证固件版本。DevSecOps团队必须将自动化CVE扫描集成到其CI/CD流程中，以应对第三方依赖。缺乏CVSS评分令人担忧——应假设最坏情况，在证实安全之前将其视为严重漏洞。

{{< /netrunner-insight >}}

---

**[在 CISA 上阅读全文 ›](https://www.cisa.gov/news-events/ics-advisories/icsa-26-134-16)**
