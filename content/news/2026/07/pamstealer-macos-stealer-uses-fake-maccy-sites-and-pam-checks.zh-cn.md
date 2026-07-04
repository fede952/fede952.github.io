---
title: "PamStealer macOS 窃密软件利用虚假 Maccy 网站和 PAM 检查"
date: "2026-07-04T09:17:53Z"
original_date: "2026-07-03T08:03:37"
lang: "zh-cn"
translationKey: "pamstealer-macos-stealer-uses-fake-maccy-sites-and-pam-checks"
author: "NewsBot (Validated by Federico Sella)"
description: "Jamf Threat Labs 发现 PamStealer，一种通过虚假 Maccy 网站分发的 macOS 信息窃取软件，利用 PAM 检查窃取登录密码。"
original_url: "https://thehackernews.com/2026/07/pamstealer-uses-fake-maccy-sites-and.html"
source: "The Hacker News"
severity: "High"
target: "macOS 用户"
cve: null
cvss: null
kev: null
tags: ["news", "cybersecurity"]
news-categories: ["cybersecurity"]
layout: "news"
draft: false
---

Jamf Threat Labs 发现 PamStealer，一种通过虚假 Maccy 网站分发的 macOS 信息窃取软件，利用 PAM 检查窃取登录密码。

{{< cyber-report severity="High" source="The Hacker News" target="macOS 用户" >}}

Jamf Threat Labs 的网络安全研究人员发现了一种名为 PamStealer 的新型 macOS 信息窃取软件。该恶意软件以编译后的 AppleScript (.scpt) 文件形式分发，冒充合法的开源剪贴板管理器 Maccy。它采用一系列巧妙技巧感染系统并窃取敏感数据，包括登录密码。

{{< ad-banner >}}

PamStealer 得名于其滥用 macOS 可插拔认证模块（PAM）框架的能力。通过拦截认证过程，它可以在用户登录或进行特权操作时捕获用户凭证。然后，该窃取软件将窃取的数据外泄到攻击者控制的服务器。

该活动依赖虚假网站和社会工程学手段诱骗用户下载恶意的 .scpt 文件。一旦执行，恶意软件会执行 PAM 检查以窃取密码而不引起怀疑。拥有 macOS 终端的组织应监控异常的 .scpt 文件执行和与 PAM 相关的异常行为。

{{< netrunner-insight >}}

对于 SOC 分析师而言，这凸显了需要监控 macOS 终端上编译的 AppleScript 执行和 PAM 修改。DevSecOps 团队应强制执行应用程序白名单，并教育用户验证软件来源，尤其是剪贴板管理器。实施针对 PAM 滥用的端点检测规则有助于及早捕获此窃取软件。

{{< /netrunner-insight >}}

---

**[在 The Hacker News 上阅读全文 ›](https://thehackernews.com/2026/07/pamstealer-uses-fake-maccy-sites-and.html)**
