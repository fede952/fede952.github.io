---
title: "CSS攻击突破电子邮件边界以窃取密码和令牌"
date: "2026-08-09T07:52:16Z"
original_date: "2026-08-08T08:03:57"
lang: "zh-cn"
translationKey: "css-attacks-escape-email-boundaries-to-steal-passwords-and-tokens"
slug: "css-attacks-escape-email-boundaries-to-steal-passwords-and-tokens"
author: "NewsBot (Validated by Federico Sella)"
description: "新研究揭示了基于CSS的攻击，这些攻击突破电子邮件内容以劫持网页邮件界面，在主要提供商中窃取凭据和令牌。"
original_url: "https://thehackernews.com/2026/08/new-css-attacks-can-break-webmail.html"
source: "The Hacker News"
severity: "High"
target: "网页邮件界面（Outlook、Gmail等）"
cve: null
cvss: null
kev: null
tags: ["news", "cybersecurity"]
news-categories: ["cybersecurity"]
layout: "news"
draft: false
---

新研究揭示了基于CSS的攻击，这些攻击突破电子邮件内容以劫持网页邮件界面，在主要提供商中窃取凭据和令牌。

{{< cyber-report severity="High" source="The Hacker News" target="网页邮件界面（Outlook、Gmail等）" >}}

来自PortSwigger的安全研究员Gareth发现了一类新型攻击，利用CSS打破电子邮件内容与周围网页邮件界面之间的预期隔离。通过构造恶意电子邮件，攻击者可以使内容逃逸出其消息边界并干扰网页邮件自身的UI，从而可能捕获密码、窃取会话令牌以及劫持受信任的用户操作。

{{< ad-banner >}}

该研究展示了影响主要网页邮件提供商（包括Outlook、Gmail、Fastmail、Proton Mail、Yahoo Mail和AOL Mail）的攻击链。除了凭据窃取外，这些技术还可用于接管第三方账户、泄露敏感令牌，甚至操纵读取电子邮件的AI工具，显著扩大了攻击面。

这些发现凸显了网页邮件客户端渲染不受信任内容时的根本弱点。虽然尚未分配具体的CVE，但影响严重，依赖网页邮件的组织应监控更新并考虑增加额外的安全层以减轻潜在利用。

{{< netrunner-insight >}}

这项研究强调，电子邮件不仅是恶意软件的载体，还可以成为针对用户信任的界面的武器。SOC分析师应将可疑电子邮件视为潜在的UI破坏载荷，而不仅仅是网络钓鱼诱饵。DevSecOps团队应审查其网页邮件客户端如何对内容进行沙箱隔离，并考虑强制执行严格的内容安全策略（CSP）头以限制基于CSS的逃逸尝试。

{{< /netrunner-insight >}}

---

**[在 The Hacker News 上阅读全文 ›](https://thehackernews.com/2026/08/new-css-attacks-can-break-webmail.html)**
