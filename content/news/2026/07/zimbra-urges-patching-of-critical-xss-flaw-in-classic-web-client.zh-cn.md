---
title: "Zimbra 敦促修补经典网页客户端中的严重 XSS 漏洞"
date: "2026-07-11T08:46:58Z"
original_date: "2026-07-10T11:47:38"
lang: "zh-cn"
translationKey: "zimbra-urges-patching-of-critical-xss-flaw-in-classic-web-client"
slug: "zimbra-urges-patching-of-critical-xss-flaw-in-classic-web-client"
author: "NewsBot (Validated by Federico Sella)"
description: "Zimbra 警告客户修补影响 Zimbra Collaboration 套件经典网页客户端的跨站脚本漏洞。"
original_url: "https://www.bleepingcomputer.com/news/security/zimbra-urges-customers-to-patch-critical-web-client-xss-flaw/"
source: "BleepingComputer"
severity: "Critical"
target: "Zimbra Collaboration 经典网页客户端"
cve: null
cvss: null
kev: null
tags: ["news", "cybersecurity"]
news-categories: ["cybersecurity"]
layout: "news"
draft: false
---

Zimbra 警告客户修补影响 Zimbra Collaboration 套件经典网页客户端的跨站脚本漏洞。

{{< cyber-report severity="Critical" source="BleepingComputer" target="Zimbra Collaboration 经典网页客户端" >}}

Zimbra 已发布紧急公告，敦促客户修补 Zimbra Collaboration 套件经典网页客户端中的一个严重漏洞。该漏洞是一个跨站脚本（XSS）问题，可能允许攻击者在用户会话上下文中执行任意脚本，从而导致数据窃取或账户接管。

{{< ad-banner >}}

该漏洞影响所有版本的经典网页客户端，Zimbra 已发布补丁解决此问题。强烈建议管理员立即应用更新以降低被利用的风险。目前尚未披露 CVE 标识符或 CVSS 评分。

鉴于该漏洞的严重性以及 Zimbra 在企业环境中的广泛使用，此漏洞构成了重大威胁。使用 Zimbra 的组织应优先进行修补，并检查其网页客户端配置是否存在任何受损迹象。

{{< netrunner-insight >}}

这是一个在广泛部署的电子邮件协作平台中的典型 XSS 漏洞。SOC 分析师应立即检查是否存在任何异常的客户端活动或意外重定向。DevSecOps 团队应优先修补，并考虑添加 WAF 规则以阻止针对经典网页客户端的常见 XSS 载荷。

{{< /netrunner-insight >}}

---

**[在 BleepingComputer 上阅读全文 ›](https://www.bleepingcomputer.com/news/security/zimbra-urges-customers-to-patch-critical-web-client-xss-flaw/)**
