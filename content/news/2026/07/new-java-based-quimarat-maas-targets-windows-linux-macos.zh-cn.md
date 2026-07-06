---
title: "新型基于Java的QuimaRAT MaaS威胁Windows、Linux和macOS系统"
date: "2026-07-06T11:23:53Z"
original_date: "2026-07-06T08:13:33"
lang: "zh-cn"
translationKey: "new-java-based-quimarat-maas-targets-windows-linux-macos"
slug: "new-java-based-quimarat-maas-targets-windows-linux-macos"
author: "NewsBot (Validated by Federico Sella)"
description: "QuimaRAT是一款跨平台的Java RAT，以恶意软件即服务的形式出售，威胁Windows、Linux和macOS系统。LevelBlue的研究人员详细介绍了其订阅模式及功能。"
original_url: "https://thehackernews.com/2026/07/new-java-based-quimarat-maas-built-to.html"
source: "The Hacker News"
severity: "High"
target: "Windows、Linux和macOS系统"
cve: null
cvss: null
kev: null
tags: ["news", "cybersecurity"]
news-categories: ["cybersecurity"]
layout: "news"
draft: false
---

QuimaRAT是一款跨平台的Java RAT，以恶意软件即服务的形式出售，威胁Windows、Linux和macOS系统。LevelBlue的研究人员详细介绍了其订阅模式及功能。

{{< cyber-report severity="High" source="The Hacker News" target="Windows、Linux和macOS系统" >}}

LevelBlue的网络安全研究人员发现了一种名为QuimaRAT的新型基于Java的远程访问木马（RAT），该木马能够针对Windows、Linux和macOS环境。该恶意软件以恶意软件即服务（MaaS）模式进行销售，订阅层级从每月150美元到终身访问1200美元不等，此外还有300美元的层级。

{{< ad-banner >}}

QuimaRAT的跨平台特性得益于Java，使其能够入侵多种操作系统，对拥有异构环境的组织构成多面威胁。MaaS模式降低了技术能力较弱的威胁行为者的入门门槛，可能增加攻击频率。

尽管初步报告中关于QuimaRAT功能的具体技术细节有限，但其基于Java的架构表明它可能利用常见技术，如键盘记录、屏幕捕获和文件窃取。组织应监控可疑的Java进程，并实施应用程序白名单以降低风险。

{{< netrunner-insight >}}

对于SOC分析师而言，QuimaRAT的跨平台特性意味着检测规则必须覆盖Windows、Linux和macOS端点。DevSecOps团队应审查Java运行时的使用情况，并考虑限制未签名Java应用程序的执行。鉴于MaaS模式，预计低技术水平的攻击者会部署此RAT，因此对异常网络连接和进程行为进行基线监控至关重要。

{{< /netrunner-insight >}}

---

**[在 The Hacker News 上阅读全文 ›](https://thehackernews.com/2026/07/new-java-based-quimarat-maas-built-to.html)**
