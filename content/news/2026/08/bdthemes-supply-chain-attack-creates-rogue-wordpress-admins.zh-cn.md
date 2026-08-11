---
title: "BdThemes供应链攻击创建恶意WordPress管理员账户"
date: "2026-08-11T08:10:19Z"
original_date: "2026-08-11T05:48:44"
lang: "zh-cn"
translationKey: "bdthemes-supply-chain-attack-creates-rogue-wordpress-admins"
slug: "bdthemes-supply-chain-attack-creates-rogue-wordpress-admins"
author: "NewsBot (Validated by Federico Sella)"
description: "供应链攻击波及BdThemes WordPress插件；源代码零修改，但恶意JSON创建了恶意管理员账户。"
original_url: "https://thehackernews.com/2026/08/bdthemes-supply-chain-attack-poisons.html"
source: "The Hacker News"
severity: "High"
target: "使用BdThemes插件的WordPress网站"
cve: null
cvss: null
kev: null
tags: ["news", "cybersecurity"]
news-categories: ["cybersecurity"]
layout: "news"
draft: false
---

供应链攻击波及BdThemes WordPress插件；源代码零修改，但恶意JSON创建了恶意管理员账户。

{{< cyber-report severity="High" source="The Hacker News" target="使用BdThemes插件的WordPress网站" >}}

网络安全研究人员披露了一起针对WordPress插件供应商BdThemes的供应链攻击。此次入侵导致WordPress插件团队暂时禁用了插件下载。值得注意的是，这次攻击与典型的供应链事件不同：WordPress.org官方仓库中的源代码文件未被修改。

{{< ad-banner >}}

相反，该攻击利用恶意JSON载荷创建恶意WordPress管理员账户。这种技术使攻击者无需修改核心插件文件即可获得对受影响站点的未授权访问，使得标准完整性检查更难检测到。

Wordfence研究员Paolo Tresso强调了这次攻击的异常性质，指出源代码未被修改这一事实凸显了超越代码完整性进行全面供应链监控的必要性。

{{< netrunner-insight >}}

这次攻击强调了不仅监控代码变更，还要监控配置和数据文件（如JSON）的重要性。对于SOC分析师，将插件更新视为高风险事件，并验证所有文件的完整性，而不仅仅是源代码。DevSecOps应实施运行时监控以检测意外的管理员账户创建，并考虑覆盖非代码资产的文件完整性监控。

{{< /netrunner-insight >}}

---

**[在 The Hacker News 上阅读全文 ›](https://thehackernews.com/2026/08/bdthemes-supply-chain-attack-poisons.html)**
