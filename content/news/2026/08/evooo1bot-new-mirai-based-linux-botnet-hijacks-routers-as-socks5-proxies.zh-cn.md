---
title: "Evooo1Bot：基于Mirai的新型Linux僵尸网络劫持路由器作为SOCKS5代理"
date: "2026-08-16T07:24:07Z"
original_date: "2026-08-15T14:14:38"
lang: "zh-cn"
translationKey: "evooo1bot-new-mirai-based-linux-botnet-hijacks-routers-as-socks5-proxies"
slug: "evooo1bot-new-mirai-based-linux-botnet-hijacks-routers-as-socks5-proxies"
author: "NewsBot (Validated by Federico Sella)"
description: "Evooo1Bot，一种模块化的Mirai变体，针对面向互联网的网关设备，将路由器转变为SOCKS5中继节点，用于隐蔽流量传输。"
original_url: "https://www.bleepingcomputer.com/news/security/new-evooo1bot-linux-botnet-turns-routers-into-traffic-relay-nodes/"
source: "BleepingComputer"
severity: "High"
target: "面向互联网的网关设备"
cve: null
cvss: null
kev: null
tags: ["news", "cybersecurity"]
news-categories: ["cybersecurity"]
layout: "news"
draft: false
---

Evooo1Bot，一种模块化的Mirai变体，针对面向互联网的网关设备，将路由器转变为SOCKS5中继节点，用于隐蔽流量传输。

{{< cyber-report severity="High" source="BleepingComputer" target="面向互联网的网关设备" >}}

一个名为Evooo1Bot的基于Mirai的新型Linux僵尸网络已被观察到针对面向互联网的网关设备，如路由器和其他网络设备。该恶意软件采用模块化设计，允许在初始感染后添加新功能。

{{< ad-banner >}}

一旦感染，被入侵的设备会被重新用作SOCKS5流量中继节点。这使得僵尸网络操作者能够通过被劫持路由器的分布式网络路由恶意流量，从而掩盖攻击来源，并可能规避基于网络的防御。

使用SOCKS5中继是相对于典型Mirai DDoS功能的一个显著演变，表明其向更隐蔽的基于代理的操作转变。组织应确保网关设备已打补丁，更改默认凭据，并且远程管理接口不暴露于互联网。

{{< netrunner-insight >}}

对于SOC分析师来说，这凸显了监控网络设备异常出站连接的重要性，因为SOCKS5中继可用于隧道传输恶意流量。DevSecOps团队应通过禁用未使用的服务、强制强认证和分段管理接口来加固网关设备。主动威胁狩猎Mirai变体至关重要，因为它们继续超越简单的DDoS工具而演变。

{{< /netrunner-insight >}}

---

**[在 BleepingComputer 上阅读全文 ›](https://www.bleepingcomputer.com/news/security/new-evooo1bot-linux-botnet-turns-routers-into-traffic-relay-nodes/)**
