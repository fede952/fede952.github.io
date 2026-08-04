---
title: "恶意npm包针对阿里巴巴工具用户，投放跨平台RAT"
date: "2026-08-04T09:40:19Z"
original_date: "2026-08-03T18:43:53"
lang: "zh-cn"
translationKey: "malicious-npm-packages-target-alibaba-tool-users-with-cross-platform-rat"
slug: "malicious-npm-packages-target-alibaba-tool-users-with-cross-platform-rat"
author: "NewsBot (Validated by Federico Sella)"
description: "研究人员发现18个恶意npm包，包括“lib-mtop”，在定向供应链攻击中向阿里巴巴开发者工具用户投放跨平台RAT。"
original_url: "https://thehackernews.com/2026/08/18-malicious-npm-packages-deliver-cross.html"
source: "The Hacker News"
severity: "High"
target: "阿里巴巴开发者工具用户"
cve: null
cvss: null
kev: null
tags: ["news", "cybersecurity"]
news-categories: ["cybersecurity"]
layout: "news"
draft: false
---

研究人员发现18个恶意npm包，包括“lib-mtop”，在定向供应链攻击中向阿里巴巴开发者工具用户投放跨平台RAT。

{{< cyber-report severity="High" source="The Hacker News" target="阿里巴巴开发者工具用户" >}}

网络安全研究人员发现了一组新的18个恶意npm包，旨在针对阿里巴巴开发者工具的用户。该攻击是复杂、定向的软件供应链活动的一部分，特别针对中文环境，表明攻击者进行了高水平的侦察和本地化。

{{< ad-banner >}}

其中一个名为“lib-mtop”的包是一个无作用域包，与阿里巴巴私有包同名，这是一种典型的仿冒（typosquatting）技术。这表明攻击者试图欺骗那些可能错误安装恶意包而不是合法包的开发者，从而在他们的开发环境中获得立足点。

这些恶意包向受害者投放跨平台远程访问木马（RAT），使攻击者能够远程控制受感染的系统。RAT的跨平台特性表明它旨在影响广泛的操作系统，从而增加攻击的潜在影响。

{{< netrunner-insight >}}

这次攻击强调了验证包真实性的重要性，尤其是在使用私有或内部包时。SOC分析师和DevSecOps工程师应实施严格的包来源检查，例如使用锁文件和验证包完整性，并监控开发机器上的意外网络连接。此外，考虑使用带有白名单的私有注册表以防止仿冒攻击。

{{< /netrunner-insight >}}

---

**[在 The Hacker News 上阅读全文 ›](https://thehackernews.com/2026/08/18-malicious-npm-packages-deliver-cross.html)**
