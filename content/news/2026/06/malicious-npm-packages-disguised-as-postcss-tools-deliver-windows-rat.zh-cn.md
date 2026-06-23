---
title: "伪装成PostCSS工具的恶意npm包传播Windows远程访问木马"
date: "2026-06-23T10:35:14Z"
original_date: "2026-06-23T08:54:32"
lang: "zh-cn"
translationKey: "malicious-npm-packages-disguised-as-postcss-tools-deliver-windows-rat"
author: "NewsBot (Validated by Federico Sella)"
description: "三个伪装成PostCSS工具的恶意npm包被发现用于传播Windows远程访问木马。研究人员提醒安装npm包时需谨慎。"
original_url: "https://thehackernews.com/2026/06/malicious-npm-packages-pose-as-postcss.html"
source: "The Hacker News"
severity: "High"
target: "npm用户、Windows系统"
cve: null
cvss: null
kev: null
tags: ["news", "cybersecurity"]
news-categories: ["cybersecurity"]
layout: "news"
draft: false
---

三个伪装成PostCSS工具的恶意npm包被发现用于传播Windows远程访问木马。研究人员提醒安装npm包时需谨慎。

{{< cyber-report severity="High" source="The Hacker News" target="npm用户、Windows系统" >}}

网络安全研究人员识别出三个恶意npm包——aes-decode-runner-pro、postcss-minify-selector和postcss-minify-selector-parser——它们旨在传播基于Windows的远程访问木马（RAT）。这些包在过去一个月内由一名npm用户发布，累计下载量达1016次，表明其传播范围虽中等但令人担忧。

{{< ad-banner >}}

这些包伪装成合法的PostCSS工具（一种流行的CSS后处理器），诱骗开发者安装。一旦安装，恶意代码会执行有效载荷，建立对受感染Windows机器的远程访问，可能使攻击者能够窃取数据、安装其他恶意软件或在网络内横向移动。

此事件凸显了npm生态系统中持续存在的域名抢注和依赖混淆威胁。建议开发者在安装前仔细验证包名、审查源代码，并使用包完整性验证工具来降低此类风险。

{{< netrunner-insight >}}

对于SOC分析师和DevSecOps工程师而言，这提醒我们要严格执行包来源检查，并监控异常的npm包安装。考虑实施自动扫描以检测已知恶意包，并教育开发者不要盲目信任包名。相对较低的下载量表明此活动可能处于早期阶段，因此主动搜寻类似包是必要的。

{{< /netrunner-insight >}}

---

**[在 The Hacker News 上阅读全文 ›](https://thehackernews.com/2026/06/malicious-npm-packages-pose-as-postcss.html)**
