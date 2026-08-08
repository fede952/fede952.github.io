---
title: "近800个恶意npm包传播跨平台RAT和窃密木马"
date: "2026-08-08T07:43:01Z"
original_date: "2026-08-07T18:48:17"
lang: "zh-cn"
translationKey: "nearly-800-malicious-npm-packages-deliver-cross-platform-rat-and-infostealer"
slug: "nearly-800-malicious-npm-packages-deliver-cross-platform-rat-and-infostealer"
author: "NewsBot (Validated by Federico Sella)"
description: "一场涉及近800个恶意npm包的活动利用AI生成的拼写错误域名仿冒（typo-squatting）技术，传播针对Windows、Mac和Linux的跨平台RAT和窃密木马。"
original_url: "https://thehackernews.com/2026/08/nearly-800-malicious-npm-packages.html"
source: "The Hacker News"
severity: "High"
target: "npm注册表用户"
cve: null
cvss: null
kev: null
tags: ["news", "cybersecurity"]
news-categories: ["cybersecurity"]
layout: "news"
draft: false
---

一场涉及近800个恶意npm包的活动利用AI生成的拼写错误域名仿冒（typo-squatting）技术，传播针对Windows、Mac和Linux的跨平台RAT和窃密木马。

{{< cyber-report severity="High" source="The Hacker News" target="npm注册表用户" >}}

根据OpenSourceMalware研究员Paul的报告，发现了一场新活动，向npm注册表发布了近800个恶意包。这些包旨在传播跨平台远程访问木马（RAT）和窃密木马载荷，影响Windows、macOS和Linux系统。

{{< ad-banner >}}

这些恶意包似乎使用了“AI生成拼写错误”或随机生成的typo-squatting包名，这种技术利用AI生成的名称来逃避检测并诱骗开发者安装它们。一旦安装，该载荷为攻击者提供远程访问能力，并能够从受感染的系统中窃取敏感信息。

此活动凸显了通过包注册表进行供应链攻击的持续风险。建议开发者和组织仔细审查包名，验证发布者身份，并采用自动化安全扫描来检测和阻止此类恶意包，以防造成危害。

{{< netrunner-insight >}}

对于SOC分析师和DevSecOps工程师，此活动强调了强大的包来源验证和运行时监控的必要性。实施自动化工具来标记可疑的包名和行为，并考虑使用具有严格白名单的私有注册表。此外，教育开发者了解typo-squatting的风险，并鼓励他们在安装前仔细检查包名。

{{< /netrunner-insight >}}

---

**[在 The Hacker News 上阅读全文 ›](https://thehackernews.com/2026/08/nearly-800-malicious-npm-packages.html)**
