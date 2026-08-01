---
title: "酒店Wi-Fi上的虚假浏览器更新传播CornFlake远程访问木马"
date: "2026-08-01T09:04:02Z"
original_date: "2026-08-01T06:29:05"
lang: "zh-cn"
translationKey: "fake-browser-update-on-hotel-wi-fi-delivers-cornflake-rat"
slug: "fake-browser-update-on-hotel-wi-fi-delivers-cornflake-rat"
author: "NewsBot (Validated by Federico Sella)"
description: "微软警告CaptiveCrunch行动利用被劫持的酒店Wi-Fi推送虚假更新并传播CornFlake监控恶意软件。"
original_url: "https://thehackernews.com/2026/08/hijacked-hotel-wi-fi-pushes-fake.html"
source: "The Hacker News"
severity: "High"
target: "酒店Wi-Fi用户"
cve: null
cvss: null
kev: null
tags: ["news", "cybersecurity"]
news-categories: ["cybersecurity"]
layout: "news"
draft: false
---

微软警告CaptiveCrunch行动利用被劫持的酒店Wi-Fi推送虚假更新并传播CornFlake监控恶意软件。

{{< cyber-report severity="High" source="The Hacker News" target="酒店Wi-Fi用户" >}}

微软披露了一项名为CaptiveCrunch的新活动，该活动利用被劫持的酒店Wi-Fi网络提供虚假的浏览器更新。这些更新实际上是一种名为CornFlake的远程访问木马（RAT），能够捕获摄像头图像、麦克风音频和键盘输入，有效地将受感染的设备变成监控工具。

{{< ad-banner >}}

该行动归因于Storm-2945，微软评估其为知名威胁组织Midnight Blizzard的一个运营子集群。这表明其具有高度的复杂性和资源，因为攻击链涉及破坏酒店的网络基础设施，以拦截和重定向用户流量到恶意更新页面。

虽然报告未指明特定的CVE或CVSS评分，但该攻击向量因其利用受信任的环境（酒店Wi-Fi）来传递恶意软件而值得注意。旅行者和商务人士尤其面临风险，因为他们经常依赖公共Wi-Fi，并且可能更倾向于不加审查地接受浏览器更新提示。

{{< netrunner-insight >}}

此活动强调了在不可信网络上对任何浏览器更新提示保持怀疑的重要性。SOC分析师应监控最近连接过酒店或公共Wi-Fi的端点是否存在异常出站连接，并考虑阻止或标记不在组织允许列表中的更新相关域名。对于DevSecOps，实施严格的更新策略并为远程工作者使用企业级VPN可以减轻此类水坑式攻击的风险。

{{< /netrunner-insight >}}

---

**[在 The Hacker News 上阅读全文 ›](https://thehackernews.com/2026/08/hijacked-hotel-wi-fi-pushes-fake.html)**
