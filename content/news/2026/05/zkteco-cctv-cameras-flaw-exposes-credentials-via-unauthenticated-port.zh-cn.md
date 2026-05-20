---
title: "ZKTeco 闭路电视摄像头漏洞通过未授权端口泄露凭据"
date: "2026-05-20T10:24:09Z"
original_date: "2026-05-19T12:00:00"
lang: "zh-cn"
translationKey: "zkteco-cctv-cameras-flaw-exposes-credentials-via-unauthenticated-port"
author: "NewsBot (Validated by Federico Sella)"
description: "CISA 警告 ZKTeco 闭路电视摄像头存在 CVE-2026-8598 漏洞，可通过未记录端口窃取凭据。固件版本 V5.0.1.2.20260421 已提供补丁。"
original_url: "https://www.cisa.gov/news-events/ics-advisories/icsa-26-139-04"
source: "CISA"
severity: "Critical"
target: "ZKTeco 闭路电视摄像头"
cve: "CVE-2026-8598"
cvss: 9.1
kev: null
tags: ["news", "cybersecurity"]
news-categories: ["cybersecurity"]
layout: "news"
draft: false
---

CISA 警告 ZKTeco 闭路电视摄像头存在 CVE-2026-8598 漏洞，可通过未记录端口窃取凭据。固件版本 V5.0.1.2.20260421 已提供补丁。

{{< cyber-report severity="Critical" source="CISA" target="ZKTeco 闭路电视摄像头" cve="CVE-2026-8598" cvss="9.1" >}}

CISA 发布了一份公告（ICSA-26-139-04），详细说明了 ZKTeco 闭路电视摄像头中的一个严重身份验证绕过漏洞。该漏洞编号为 CVE-2026-8598，涉及一个无需身份验证即可访问的未记录配置导出端口。成功利用可能导致信息泄露，包括获取摄像头账户凭据。

{{< ad-banner >}}

该漏洞影响 ZKTeco SSC335-GC2063-Face-0b77 解决方案固件版本低于 V5.0.1.2.20260421 的设备。CVSS v3 基础评分为 9.1，表明严重程度为严重。受影响设备在全球商业设施中部署，供应商总部位于中国。

ZKTeco 已发布修补固件版本 V5.0.1.2.20260421 以解决该问题。强烈建议用户立即升级。该漏洞归类为 CWE-288（使用替代路径或通道绕过身份验证）。

{{< netrunner-insight >}}

这是一个暴露的调试接口变成后门的典型例子。SOC 分析师应立即扫描网络中的 ZKTeco 摄像头并验证固件版本。对于 DevSecOps 而言，这强调了在物联网固件构建中禁用或防火墙未记录端口的必要性。将固件版本低于 V5.0.1.2.20260421 的任何摄像头视为已受损，直到证明其安全。

{{< /netrunner-insight >}}

---

**[在 CISA 上阅读全文 ›](https://www.cisa.gov/news-events/ics-advisories/icsa-26-139-04)**
