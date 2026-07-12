---
title: "虚假Microsoft Entra通行密钥注册活动针对M365用户进行数据勒索"
date: "2026-07-12T09:00:42Z"
original_date: "2026-07-10T10:30:20"
lang: "zh-cn"
translationKey: "fake-microsoft-entra-passkey-enrollment-targets-m365-users-in-data-extortion-campaign"
slug: "fake-microsoft-entra-passkey-enrollment-targets-m365-users-in-data-extortion-campaign"
author: "NewsBot (Validated by Federico Sella)"
description: "威胁行为者O-UNC-066利用语音钓鱼诱骗用户注册虚假Entra通行密钥，旨在入侵Microsoft 365账户以实施数据勒索。"
original_url: "https://thehackernews.com/2026/07/hackers-use-fake-microsoft-entra.html"
source: "The Hacker News"
severity: "High"
target: "Microsoft 365用户"
cve: null
cvss: null
kev: null
tags: ["news", "cybersecurity"]
news-categories: ["cybersecurity"]
layout: "news"
draft: false
---

威胁行为者O-UNC-066利用语音钓鱼诱骗用户注册虚假Entra通行密钥，旨在入侵Microsoft 365账户以实施数据勒索。

{{< cyber-report severity="High" source="The Hacker News" target="Microsoft 365用户" >}}

Okta追踪为O-UNC-066的威胁行为者被发现针对多个行业的Microsoft 365用户进行语音钓鱼攻击。攻击者冒充合法的安全请求，诱骗受害者注册虚假的Entra通行密钥，从而让对手获得对其账户的未授权访问。

{{< ad-banner >}}

该活动利用一个面板控制的钓鱼工具包，专门设计用于拦截通行密钥注册过程。一旦攻击者获得访问权限，他们便试图进行数据勒索，窃取敏感信息并索要赎金。这些攻击凸显了利用语音渠道绕过传统基于电子邮件的钓鱼防御的趋势日益增长。

建议组织使用硬件安全密钥实施多因素认证（MFA），并教育用户通过其他通信渠道验证任何未经请求的安全请求。监控异常的通行密钥注册活动有助于及早发现此类攻击。

{{< netrunner-insight >}}

此次攻击强调了对待基于语音的安全请求应与对待钓鱼电子邮件持相同怀疑态度的重要性。SOC分析师应监控异常的通行密钥注册尝试，并确保MFA注册过程需要带外验证。DevSecOps团队应考虑实施条件访问策略，将通行密钥注册限制在受信任的设备与位置。

{{< /netrunner-insight >}}

---

**[在 The Hacker News 上阅读全文 ›](https://thehackernews.com/2026/07/hackers-use-fake-microsoft-entra.html)**
