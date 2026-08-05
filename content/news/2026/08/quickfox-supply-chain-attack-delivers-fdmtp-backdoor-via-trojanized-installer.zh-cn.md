---
title: "QuickFox 供应链攻击通过木马化安装程序传播 FDMTP 后门"
date: "2026-08-05T09:34:12Z"
original_date: "2026-08-05T05:47:19"
lang: "zh-cn"
translationKey: "quickfox-supply-chain-attack-delivers-fdmtp-backdoor-via-trojanized-installer"
slug: "quickfox-supply-chain-attack-delivers-fdmtp-backdoor-via-trojanized-installer"
author: "NewsBot (Validated by Federico Sella)"
description: "针对 QuickFox VPN 的长期供应链攻击将安装程序木马化，以部署 FDMTP 后门，自 2025 年 8 月以来一直以海外华人用户为目标。"
original_url: "https://thehackernews.com/2026/08/quickfox-supply-chain-attack-delivers.html"
source: "The Hacker News"
severity: "High"
target: "QuickFox VPN 用户"
cve: null
cvss: null
kev: null
tags: ["news", "cybersecurity"]
news-categories: ["cybersecurity"]
layout: "news"
draft: false
---

针对 QuickFox VPN 的长期供应链攻击将安装程序木马化，以部署 FDMTP 后门，自 2025 年 8 月以来一直以海外华人用户为目标。

{{< cyber-report severity="High" source="The Hacker News" target="QuickFox VPN 用户" >}}

Fortinet FortiGuard Labs 披露了一起针对 QuickFox 的长期供应链攻击，QuickFox 是一款在海外华人用户中流行的 VPN 和网络加速工具。该攻击至少自 2025 年 8 月以来一直活跃，涉及该应用程序 Windows 安装程序的木马化版本，该版本会传递名为 FDMTP 的后门。

{{< ad-banner >}}

木马化的安装程序通过官方或可信渠道分发，破坏了软件供应链的完整性。一旦执行，FDMTP 将为攻击者提供对受害者系统的远程访问和控制，可能导致数据窃取、监视或进一步部署恶意软件。

此事件凸显了针对小众但可信工具（尤其是服务于特定社区的工具）的供应链攻击风险日益增加。使用 QuickFox 的组织和个人应验证其安装的完整性，并监控与 FDMTP 相关的入侵指标。

{{< netrunner-insight >}}

此次攻击强调了即使对于来自看似信誉良好的供应商的工具，也需要进行强大的软件完整性验证。SOC 分析师应搜寻 FDMTP 指标，并监控来自 VPN 客户端的异常网络连接。DevSecOps 团队必须在其软件部署管道中强制执行代码签名和哈希验证，以减轻此类供应链风险。

{{< /netrunner-insight >}}

---

**[在 The Hacker News 上阅读全文 ›](https://thehackernews.com/2026/08/quickfox-supply-chain-attack-delivers.html)**
