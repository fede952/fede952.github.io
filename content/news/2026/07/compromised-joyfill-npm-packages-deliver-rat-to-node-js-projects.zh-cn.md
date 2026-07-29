---
title: "被篡改的joyfill npm包向Node.js项目投递远程访问木马"
date: "2026-07-29T09:34:53Z"
original_date: "2026-07-29T04:20:57"
lang: "zh-cn"
translationKey: "compromised-joyfill-npm-packages-deliver-rat-to-node-js-projects"
slug: "compromised-joyfill-npm-packages-deliver-rat-to-node-js-projects"
author: "NewsBot (Validated by Federico Sella)"
description: "@joyfill/layouts和@joyfill/components的测试版本包含一个导入时执行的JavaScript植入程序，该程序解析加密代码以部署远程访问木马。"
original_url: "https://thehackernews.com/2026/07/two-compromised-joyfill-npm-packages.html"
source: "The Hacker News"
severity: "High"
target: "使用joyfill包的Node.js开发者"
cve: null
cvss: null
kev: null
tags: ["news", "cybersecurity"]
news-categories: ["cybersecurity"]
layout: "news"
draft: false
---

@joyfill/layouts和@joyfill/components的测试版本包含一个导入时执行的JavaScript植入程序，该程序解析加密代码以部署远程访问木马。

{{< cyber-report severity="High" source="The Hacker News" target="使用joyfill包的Node.js开发者" >}}

@joyfill命名空间下的两个npm包——@joyfill/layouts版本0.1.2-2773.beta.0和@joyfill/components版本4.0.0-rc24-2773-beta.4——已被篡改。这些测试版本包含一个导入时执行的JavaScript植入程序，该程序解析加密代码，最终投递与DEV#POPPER恶意软件家族相关的远程访问木马（RAT）。

{{< ad-banner >}}

当这些包被导入Node.js项目时，恶意代码会执行，使攻击者能够远程访问受感染的系统。此次攻击凸显了针对npm生态系统的供应链攻击的持续风险，尤其是那些可能受到较少审查的测试版或候选发布版。

使用过这些特定版本的开发者应立即轮换凭证，扫描入侵指标，并审查其依赖树中是否存在其他可疑包。npm注册表可能已移除恶意版本，但现有安装仍然构成威胁。

{{< netrunner-insight >}}

此事件凸显了审查预发布包和实施依赖完整性检查的重要性。SOC分析师应监控Node.js应用程序的异常出站连接，而DevSecOps团队应强制实施严格的版本锁定，并使用npm audit或SCA扫描器等工具检测已知的恶意包。

{{< /netrunner-insight >}}

---

**[在 The Hacker News 上阅读全文 ›](https://thehackernews.com/2026/07/two-compromised-joyfill-npm-packages.html)**
