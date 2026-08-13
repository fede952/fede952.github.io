---
title: "2026年8月补丁星期二：421个漏洞、Lazarus零日漏洞及4个CVSS 9.8的远程代码执行漏洞"
date: "2026-08-13T08:21:14Z"
original_date: "2026-08-12T08:28:22"
lang: "zh-cn"
translationKey: "august-2026-patch-tuesday-421-flaws-lazarus-zero-day-and-4-rces-with-cvss-9-8"
slug: "august-2026-patch-tuesday-421-flaws-lazarus-zero-day-and-4-rces-with-cvss-9-8"
author: "NewsBot (Validated by Federico Sella)"
description: "微软2026年8月补丁星期二解决了421个漏洞，包括一个被Lazarus利用的WinSock驱动程序零日漏洞，以及四个未经身份验证的CVSS 9.8远程代码执行漏洞。"
original_url: "https://www.cybersecurity360.it/news/patch-tuesday-agosto-2026-un-driver-windows-il-gruppo-lazarus-e-400-vulnerabilita-sullo-sfondo/"
source: "Cybersecurity360"
severity: "Critical"
target: "Microsoft Windows WinSock驱动程序"
cve: null
cvss: 9.8
kev: null
tags: ["news", "cybersecurity"]
news-categories: ["cybersecurity"]
layout: "news"
draft: false
---

微软2026年8月补丁星期二解决了421个漏洞，包括一个被Lazarus利用的WinSock驱动程序零日漏洞，以及四个未经身份验证的CVSS 9.8远程代码执行漏洞。

{{< cyber-report severity="Critical" source="Cybersecurity360" target="Microsoft Windows WinSock驱动程序" cvss="9.8" >}}

微软2026年8月补丁星期二共解决了421个漏洞，这是一次重大更新。其中，Windows WinSock驱动程序中的一个零日漏洞已被知名朝鲜威胁行为者Lazarus集团积极利用。该零日漏洞尤其令人担忧，因为它允许攻击者提升权限或执行任意代码，可能危及受影响的系统。

{{< ad-banner >}}

除了零日漏洞外，此次更新还包括四个未经身份验证的远程代码执行（RCE）漏洞，所有漏洞的CVSS评分均为9.8。这些严重缺陷可在无需用户交互的情况下远程利用，因此成为优先修补的重点。漏洞数量之多凸显了健全补丁管理流程的重要性。

文章还强调了漏洞管理策略的转变，指出随着AI驱动的发现技术的采用，基于上下文的分类比传统的基于评分的分类更有效。这表明组织应根据自身环境和威胁态势优先处理漏洞，而不是仅仅依赖CVSS评分。

{{< netrunner-insight >}}

对于SOC分析师而言，WinSock中的Lazarus零日漏洞应被视为立即优先处理的事项，因为它已被利用。请在所有Windows终端上立即修补。DevSecOps团队应利用AI驱动的上下文对421个漏洞进行分类，重点关注面向互联网或对业务运营至关重要的漏洞，而不是仅仅追求高CVSS评分。请记住，四个CVSS 9.8的RCE漏洞是未经身份验证的，因此应在其他非关键更新之前进行修补。

{{< /netrunner-insight >}}

---

**[在 Cybersecurity360 上阅读全文 ›](https://www.cybersecurity360.it/news/patch-tuesday-agosto-2026-un-driver-windows-il-gruppo-lazarus-e-400-vulnerabilita-sullo-sfondo/)**
