---
title: "AryStinger僵尸网络劫持4000多台D-Link路由器用于代理流量"
date: "2026-06-22T12:48:45Z"
original_date: "2026-06-21T14:14:22"
lang: "zh-cn"
translationKey: "arystinger-botnet-hijacks-4000-d-link-routers-for-proxy-traffic"
author: "NewsBot (Validated by Federico Sella)"
description: "名为AryStinger的新型僵尸网络已入侵超过4000台过时的D-Link路由器，将其变成恶意流量的代理。目前尚无CVE或CVSS数据。"
original_url: "https://www.bleepingcomputer.com/news/security/arystinger-botnet-infected-thousands-of-d-link-routers-worldwide/"
source: "BleepingComputer"
severity: "Medium"
target: "过时的D-Link路由器"
cve: null
cvss: null
kev: null
tags: ["news", "cybersecurity"]
news-categories: ["cybersecurity"]
layout: "news"
draft: false
---

名为AryStinger的新型僵尸网络已入侵超过4000台过时的D-Link路由器，将其变成恶意流量的代理。目前尚无CVE或CVSS数据。

{{< cyber-report severity="Medium" source="BleepingComputer" target="过时的D-Link路由器" >}}

据BleepingComputer报道，一个此前未被记录的恶意软件僵尸网络AryStinger已入侵全球超过4000台过时的D-Link路由器。该僵尸网络将这些设备变成恶意流量的代理，使攻击者能够匿名化其活动，并可能发动进一步攻击。

{{< ad-banner >}}

被入侵的路由器据信运行着存在已知漏洞的过时固件，但报告中未披露具体的CVE标识符。该僵尸网络的基础设施和传播方法仍在分析中，但感染规模凸显了未修补物联网设备所带来的风险。

建议各组织盘点其网络设备，确保固件为最新版本，并监控可能表明代理使用的异常流量模式。初始报告中缺乏详细的技术指标，表明需要进一步调查以开发检测签名。

{{< netrunner-insight >}}

对于SOC分析师而言，这提醒我们要监控来自网络设备（尤其是老旧路由器）的意外出站连接。DevSecOps团队应强制执行固件更新策略，并考虑将物联网设备与关键网络隔离。在没有特定入侵指标的情况下，基线流量分析和设备指纹识别是发现此类僵尸网络活动的关键。

{{< /netrunner-insight >}}

---

**[在 BleepingComputer 上阅读全文 ›](https://www.bleepingcomputer.com/news/security/arystinger-botnet-infected-thousands-of-d-link-routers-worldwide/)**
