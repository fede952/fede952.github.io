---
title: "Evooo1Bot 僵尸网络将边缘设备变为 SOCKS5 代理"
date: "2026-08-18T07:31:16Z"
original_date: "2026-08-17T09:29:55"
lang: "zh-cn"
translationKey: "evooo1bot-botnet-turns-edge-devices-into-socks5-proxies"
slug: "evooo1bot-botnet-turns-edge-devices-into-socks5-proxies"
author: "NewsBot (Validated by Federico Sella)"
description: "新型 Linux 僵尸网络 Evooo1Bot 源自 Mirai，利用已知漏洞将边缘设备变为 SOCKS5 代理，用于隐蔽攻击。"
original_url: "https://thehackernews.com/2026/08/evooo1bot-linux-botnet-exploits-known.html"
source: "The Hacker News"
severity: "High"
target: "面向互联网的边缘设备"
cve: null
cvss: null
kev: null
tags: ["news", "cybersecurity"]
news-categories: ["cybersecurity"]
layout: "news"
draft: false
---

新型 Linux 僵尸网络 Evooo1Bot 源自 Mirai，利用已知漏洞将边缘设备变为 SOCKS5 代理，用于隐蔽攻击。

{{< cyber-report severity="High" source="The Hacker News" target="面向互联网的边缘设备" >}}

网络安全研究人员发现了一个此前未被记录的 Linux 僵尸网络家族，名为 Evooo1Bot，其核心功能源自公开泄露的 Mirai 僵尸网络源代码。该恶意软件旨在将面向互联网的设备变为 SOCKS5 代理，使攻击者能够通过受感染的设备路由恶意流量。

{{< ad-banner >}}

虽然 Evooo1Bot 重用了 Mirai 的 DDoS 引擎，但它扩展了原始框架，增加了额外功能，包括利用边缘设备中的已知漏洞的能力。这使得僵尸网络能够扩大其影响范围，并在受感染的系统上保持持久性。

这一发现凸显了基于 Mirai 的僵尸网络的持续演变，这些僵尸网络由于能够将易受攻击的物联网和边缘设备招募到大规模代理网络中，仍然构成重大威胁。建议各组织修补已知漏洞，并监控异常的代理流量。

{{< netrunner-insight >}}

对于 SOC 分析师而言，该僵尸网络强调了监控出站代理流量和检测异常 SOCKS5 连接的重要性。DevSecOps 团队应优先修补边缘设备中的已知漏洞，并考虑网络分段以限制此类僵尸网络的影响。由于重用了 Mirai 代码，现有的检测签名可能需要更新以捕获这种新变种。

{{< /netrunner-insight >}}

---

**[在 The Hacker News 上阅读全文 ›](https://thehackernews.com/2026/08/evooo1bot-linux-botnet-exploits-known.html)**
