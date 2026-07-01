---
title: "RustDuck僵尸网络劫持路由器和摄像头用于DDoS攻击"
date: "2026-07-01T10:41:08Z"
original_date: "2026-06-30T17:45:25"
lang: "zh-cn"
translationKey: "rustduck-botnet-hijacks-routers-cameras-for-ddos"
author: "NewsBot (Validated by Federico Sella)"
description: "一种名为RustDuck的新型两阶段恶意软件家族自2026年2月以来一直被追踪，它劫持家用路由器、IP摄像头、安卓盒子以及安全性较差的服务器，构建DDoS网络。"
original_url: "https://thehackernews.com/2026/06/rustduck-botnet-rebuilds-in-rust-to.html"
source: "The Hacker News"
severity: "High"
target: "路由器、IP摄像头、安卓盒子、服务器"
cve: null
cvss: null
kev: null
tags: ["news", "cybersecurity"]
news-categories: ["cybersecurity"]
layout: "news"
draft: false
---

一种名为RustDuck的新型两阶段恶意软件家族自2026年2月以来一直被追踪，它劫持家用路由器、IP摄像头、安卓盒子以及安全性较差的服务器，构建DDoS网络。

{{< cyber-report severity="High" source="The Hacker News" target="路由器、IP摄像头、安卓盒子、服务器" >}}

奇安信XLab的研究人员自2026年2月以来一直在追踪一种名为RustDuck的新型两阶段恶意软件家族。该僵尸网络劫持家用路由器、IP摄像头、安卓盒子以及安全性较差的服务器，将它们整合成一个网络，旨在通过DDoS攻击使网站和在线服务离线。

{{< ad-banner >}}

该恶意软件因使用Rust语言重写而引人注目，Rust是一种内存安全语言，增加了分析和逆向工程的难度。虽然该僵尸网络目前的规模并不庞大，但其快速演变和适应性对互联网基础设施构成了日益增长的威胁。

RustDuck代表了僵尸网络开发的一个转变，它利用Rust的性能和安全性特性来创建更具弹性和更难检测的恶意软件。最终目标是建立一个能够击垮主要目标的强大DDoS网络。

{{< netrunner-insight >}}

对于SOC分析师：监控来自物联网设备和路由器的异常出站流量，因为RustDuck的两阶段感染可能规避传统签名。DevSecOps团队应实施严格的网络分段，并禁用暴露设备上的不必要服务，以减少攻击面。

{{< /netrunner-insight >}}

---

**[在 The Hacker News 上阅读全文 ›](https://thehackernews.com/2026/06/rustduck-botnet-rebuilds-in-rust-to.html)**
