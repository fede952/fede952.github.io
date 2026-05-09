---
title: "新型PamDOORa Linux后门通过PAM窃取SSH凭据"
date: "2026-05-09T08:29:08Z"
original_date: "2026-05-08T08:41:00"
lang: "zh-cn"
translationKey: "new-pamdoora-linux-backdoor-steals-ssh-credentials-via-pam"
author: "NewsBot (Validated by Federico Sella)"
description: "一款名为PamDOORa的新型Linux后门在俄罗斯网络犯罪论坛上以1600美元出售，利用PAM模块通过魔法密码和TCP端口组合提供持久的SSH访问。"
original_url: "https://thehackernews.com/2026/05/new-linux-pamdoora-backdoor-uses-pam.html"
source: "The Hacker News"
severity: "High"
target: "Linux SSH服务器"
cve: null
cvss: null
kev: null
tags: ["news", "cybersecurity"]
news-categories: ["cybersecurity"]
layout: "news"
draft: false
---

一款名为PamDOORa的新型Linux后门在俄罗斯网络犯罪论坛上以1600美元出售，利用PAM模块通过魔法密码和TCP端口组合提供持久的SSH访问。

{{< cyber-report severity="High" source="The Hacker News" target="Linux SSH服务器" >}}

网络安全研究人员发现了一款名为PamDOORa的新型Linux后门，该后门由威胁行为者“darkworm”在Rehub俄罗斯网络犯罪论坛上以1600美元的价格进行广告宣传。该后门被设计为基于可插拔认证模块（PAM）的后利用工具包，通过魔法密码和特定TCP端口的组合实现持久的SSH访问。

{{< ad-banner >}}

PamDOORa通过恶意PAM模块拦截SSH认证，使攻击者能够绕过正常凭据并获得未授权访问。使用PAM模块使得后门具有隐蔽性，因为它集成到Linux系统的标准认证流程中。

此类工具在网络犯罪论坛上的销售凸显了复杂攻击工具的商品化趋势。建议组织监控异常的SSH认证模式，并确保定期审计PAM配置。

{{< netrunner-insight >}}

对于SOC分析师而言，检测PamDOORa需要监控非标准端口上的意外SSH连接，并与PAM模块变更进行关联。DevSecOps团队应强制执行严格的PAM配置管理，并考虑对/etc/pam.d/及相关库进行文件完整性监控。该后门强调了将PAM视为关键安全边界的重要性。

{{< /netrunner-insight >}}

---

**[在 The Hacker News 上阅读全文 ›](https://thehackernews.com/2026/05/new-linux-pamdoora-backdoor-uses-pam.html)**
