---
title: "ABB B&R工控机遭多个CVE漏洞攻击：远程代码执行、拒绝服务、DNS投毒"
date: "2026-05-22T10:21:58Z"
original_date: "2026-05-21T12:00:00"
lang: "zh-cn"
translationKey: "abb-b-r-pcs-hit-by-multiple-cves-rce-dos-dns-poisoning"
author: "NewsBot (Validated by Federico Sella)"
description: "CISA警告ABB B&R工控机存在漏洞。已有更新可用。攻击者可实现远程代码执行、拒绝服务、DNS缓存投毒或数据窃取。"
original_url: "https://www.cisa.gov/news-events/ics-advisories/icsa-26-141-02"
source: "CISA"
severity: "High"
target: "ABB B&R工控机"
cve: "CVE-2023-45229"
cvss: null
kev: null
tags: ["news", "cybersecurity"]
news-categories: ["cybersecurity"]
layout: "news"
draft: false
---

CISA警告ABB B&R工控机存在漏洞。已有更新可用。攻击者可实现远程代码执行、拒绝服务、DNS缓存投毒或数据窃取。

{{< cyber-report severity="High" source="CISA" target="ABB B&R工控机" cve="CVE-2023-45229" >}}

ABB披露了影响多个B&R工控机产品系列的漏洞，包括APC4100、APC910、C80、MPC3100、PPC1200、PPC900和APC2200。这些漏洞编号为CVE-2023-45229至CVE-2023-45237，允许基于网络的攻击者执行远程代码、发起拒绝服务攻击、投毒DNS缓存或窃取敏感信息。

{{< ad-banner >}}

公告列出了每个产品的受影响版本，并提供了更新以修复问题。例如，APC4100版本低于1.09的受影响，而1.09版本已修复。同样，APC910版本1.25及以下受影响。ABB建议立即升级到最新固件版本。

鉴于工业控制系统（ICS）背景，这些漏洞对运营技术环境构成重大风险。使用受影响ABB B&R工控机的组织应优先进行修补，尤其是当设备暴露于不可信网络时。

{{< netrunner-insight >}}

对于SOC分析师，监控网络流量中来自B&R工控机的异常DNS查询或意外连接。DevSecOps团队应清点所有受影响设备并尽快应用固件更新，因为这些CVE无需认证即可实现远程代码执行。考虑对ICS网络进行分段以限制暴露。

{{< /netrunner-insight >}}

---

**[在 CISA 上阅读全文 ›](https://www.cisa.gov/news-events/ics-advisories/icsa-26-141-02)**
