---
title: "CISA 警告：西门子 RUGGEDCOM APE1808 设备通过 PAN-OS 存在严重缓冲区溢出漏洞"
date: "2026-05-20T10:21:56Z"
original_date: "2026-05-19T12:00:00"
lang: "zh-cn"
translationKey: "cisa-warns-of-critical-buffer-overflow-in-siemens-ruggedcom-ape1808-via-pan-os"
author: "NewsBot (Validated by Federico Sella)"
description: "Palo Alto Networks PAN-OS Captive Portal 中的缓冲区溢出漏洞影响西门子 RUGGEDCOM APE1808 设备。CVE-2026-0300 允许未经身份验证的远程攻击者以 root 权限执行任意代码。"
original_url: "https://www.cisa.gov/news-events/ics-advisories/icsa-26-139-02"
source: "CISA"
severity: "Critical"
target: "西门子 RUGGEDCOM APE1808 设备"
cve: "CVE-2026-0300"
cvss: 10.0
kev: null
tags: ["news", "cybersecurity"]
news-categories: ["cybersecurity"]
layout: "news"
draft: false
---

Palo Alto Networks PAN-OS Captive Portal 中的缓冲区溢出漏洞影响西门子 RUGGEDCOM APE1808 设备。CVE-2026-0300 允许未经身份验证的远程攻击者以 root 权限执行任意代码。

{{< cyber-report severity="Critical" source="CISA" target="西门子 RUGGEDCOM APE1808 设备" cve="CVE-2026-0300" cvss="10.0" >}}

CISA 发布了一份公告（ICSA-26-139-02），详细说明了 Palo Alto Networks PAN-OS 软件中 User-ID Authentication Portal（Captive Portal）服务存在的一个严重缓冲区溢出漏洞。该漏洞编号为 CVE-2026-0300，CVSS 评分为 10.0，允许未经身份验证的攻击者通过发送特制数据包，在 PA 系列和 VM 系列防火墙上以 root 权限执行任意代码。

{{< ad-banner >}}

该漏洞影响所有版本的西门子 RUGGEDCOM APE1808 设备。西门子正在准备修复版本，并建议采用 Palo Alto Networks 上游安全通知中提供的变通方案。在补丁可用之前，组织应禁用 Captive Portal 服务（如果不需要），并限制对受影响设备的网络访问。

鉴于 CVSS 评分极高且可能导致系统完全受损，应立即采取行动。该公告针对关键制造业领域，相关设备部署在全球范围内。运营商应优先应用缓解措施，并监控任何被利用的迹象。

{{< netrunner-insight >}}

这是供应链风险的典型例子：第三方组件（PAN-OS）将严重漏洞引入工业产品。SOC 分析师应立即搜索针对 Captive Portal 端口的异常流量，并确保网络隔离以限制暴露。DevSecOps 团队必须清点所有 RUGGEDCOM APE1808 实例，并立即应用 Palo Alto Networks 上游的缓解措施。

{{< /netrunner-insight >}}

---

**[在 CISA 上阅读全文 ›](https://www.cisa.gov/news-events/ics-advisories/icsa-26-139-02)**
