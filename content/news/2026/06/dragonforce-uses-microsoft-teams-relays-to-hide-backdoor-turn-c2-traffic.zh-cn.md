---
title: "DragonForce利用Microsoft Teams中继隐藏Backdoor.Turn的C2流量"
date: "2026-06-19T11:15:07Z"
original_date: "2026-06-18T13:30:07"
lang: "zh-cn"
translationKey: "dragonforce-uses-microsoft-teams-relays-to-hide-backdoor-turn-c2-traffic"
author: "NewsBot (Validated by Federico Sella)"
description: "DragonForce勒索软件团伙部署了基于Go的自定义RAT Backdoor.Turn，将C2流量隐藏在Microsoft Teams中继中，针对一家美国大型服务公司。"
original_url: "https://thehackernews.com/2026/06/dragonforce-hackers-abuse-microsoft.html"
source: "The Hacker News"
severity: "High"
target: "美国大型服务公司"
cve: null
cvss: null
kev: null
tags: ["news", "cybersecurity"]
news-categories: ["cybersecurity"]
layout: "news"
draft: false
---

DragonForce勒索软件团伙部署了基于Go的自定义RAT Backdoor.Turn，将C2流量隐藏在Microsoft Teams中继中，针对一家美国大型服务公司。

{{< cyber-report severity="High" source="The Hacker News" target="美国大型服务公司" >}}

与DragonForce勒索软件团伙相关的威胁行为者被观察到使用一种名为Backdoor.Turn的基于Go的自定义远程访问木马（RAT），将命令与控制（C2）流量隐藏在Microsoft Teams中继基础设施中。根据Broadcom旗下的Symantec和Carbon Black的调查结果，该后门被部署在一家美国大型服务公司。

{{< ad-banner >}}

通过利用合法的Microsoft Teams中继，攻击者可以将恶意流量与正常的业务通信混合，使网络防御者更难检测。基于Go的RAT为攻击者提供了持久访问权限，并能够执行命令、窃取数据以及部署额外的有效载荷。

这种技术突显了勒索软件团伙为逃避传统网络监控工具而不断演变的策略。使用Microsoft Teams的组织应审查其安全配置，并监控异常的中继流量模式。

{{< netrunner-insight >}}

SOC分析师应监控异常的Microsoft Teams中继流量，特别是来自非标准端点或在非工作时间产生的流量。DevSecOps团队应实施严格的应用程序白名单，并检查Teams流量中可能指示C2通信的加密隧道。此次攻击强调了即使对于受信任的协作平台，也需要遵循零信任原则。

{{< /netrunner-insight >}}

---

**[在 The Hacker News 上阅读全文 ›](https://thehackernews.com/2026/06/dragonforce-hackers-abuse-microsoft.html)**
