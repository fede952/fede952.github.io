---
title: "照片ZIP钓鱼攻击酒店，植入Node.js后门"
date: "2026-06-26T10:21:21Z"
original_date: "2026-06-26T09:27:12"
lang: "zh-cn"
translationKey: "photo-zip-phishing-hits-hotels-with-node-js-implant"
author: "NewsBot (Validated by Federico Sella)"
description: "微软警告称，一场针对欧洲和亚洲酒店的活跃钓鱼活动正在利用以照片为主题的ZIP文件投放Node.js后门。"
original_url: "https://thehackernews.com/2026/06/microsoft-warns-of-photo-zip-phishing.html"
source: "The Hacker News"
severity: "High"
target: "酒店及 hospitality 组织"
cve: null
cvss: null
kev: null
tags: ["news", "cybersecurity"]
news-categories: ["cybersecurity"]
layout: "news"
draft: false
---

微软警告称，一场针对欧洲和亚洲酒店的活跃钓鱼活动正在利用以照片为主题的ZIP文件投放Node.js后门。

{{< cyber-report severity="High" source="The Hacker News" target="酒店及 hospitality 组织" >}}

自2026年4月以来，一场活跃的钓鱼活动一直针对欧洲和亚洲的酒店及 hospitality 组织。攻击者使用以照片为主题的ZIP文件作为诱饵，一旦执行，会在前台电脑上投放Node.js后门。

{{< ad-banner >}}

微软尚未将此活动归因于任何已知威胁行为者，操作者的最终目标仍不明确。该诱饵专门设计用于利用酒店的运营方式，表明这是一种量身定制的社会工程学手段。

Node.js后门为攻击者提供了进入目标网络的立足点，可能允许横向移动和数据窃取。 hospitality 行业的组织被建议对未经请求的电子邮件附件保持警惕，并监控可疑的Node.js进程。

{{< netrunner-insight >}}

SOC分析师应监控前台系统上异常的Node.js进程和出站连接。DevSecOps团队应考虑阻止从电子邮件附件执行Node.js脚本，并实施应用程序白名单以缓解此类后门。

{{< /netrunner-insight >}}

---

**[在 The Hacker News 上阅读全文 ›](https://thehackernews.com/2026/06/microsoft-warns-of-photo-zip-phishing.html)**
