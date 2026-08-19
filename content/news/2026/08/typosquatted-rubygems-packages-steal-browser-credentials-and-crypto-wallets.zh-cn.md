---
title: "拼写错误劫持的RubyGems软件包窃取浏览器凭据和加密货币钱包"
date: "2026-08-19T07:36:21Z"
original_date: "2026-08-18T11:20:00"
lang: "zh-cn"
translationKey: "typosquatted-rubygems-packages-steal-browser-credentials-and-crypto-wallets"
slug: "typosquatted-rubygems-packages-steal-browser-credentials-and-crypto-wallets"
author: "NewsBot (Validated by Federico Sella)"
description: "研究人员标记了16个拼写错误劫持的RubyGems软件包，这些软件包部署了基于Windows的信息窃取器，目标是浏览器凭据和加密货币钱包。"
original_url: "https://thehackernews.com/2026/08/16-typosquatted-rubygems-packages-steal.html"
source: "The Hacker News"
severity: "High"
target: "Windows上的RubyGems用户"
cve: null
cvss: null
kev: null
tags: ["news", "cybersecurity"]
news-categories: ["cybersecurity"]
layout: "news"
draft: false
---

研究人员标记了16个拼写错误劫持的RubyGems软件包，这些软件包部署了基于Windows的信息窃取器，目标是浏览器凭据和加密货币钱包。

{{< cyber-report severity="High" source="The Hacker News" target="Windows上的RubyGems用户" >}}

网络安全研究人员发现了一个针对RubyGems用户的新拼写错误劫持活动，部署了基于Windows的信息窃取器。该活动被追踪为StubMaker，于2026年8月15日由OpenSourceMalware发现，涉及16个恶意软件包，旨在窃取浏览器凭据和加密货币钱包。

{{< ad-banner >}}

这些恶意软件包包括'ubnuler'、'ubnlder'、'ri18nr'、'reaker'、'rakier'、'orakw'和'joxn'等名称，很可能是流行gem的拼写错误变体，诱骗开发者安装它们。一旦安装，窃取器会从浏览器和加密货币钱包扩展中收集敏感数据，构成重大的供应链风险。

此活动凸显了开源生态系统中拼写错误劫持的持续威胁。建议开发者仔细验证软件包名称，使用可信来源，并监控项目中的可疑依赖项。

{{< netrunner-insight >}}

对于SOC分析师来说，此活动强调了监控意外RubyGems安装和可疑域名网络调用的必要性。DevSecOps工程师应强制实施严格的依赖锁定，并使用扫描拼写错误劫持软件包的工具。此外，考虑阻止已知的恶意软件包名称，并对开发者进行拼写错误劫持风险教育。

{{< /netrunner-insight >}}

---

**[在 The Hacker News 上阅读全文 ›](https://thehackernews.com/2026/08/16-typosquatted-rubygems-packages-steal.html)**
