---
title: "ShapedPlugin WordPress Pro插件在供应链攻击中被植入后门"
date: "2026-06-23T10:30:52Z"
original_date: "2026-06-22T18:00:48"
lang: "zh-cn"
translationKey: "shapedplugin-wordpress-pro-plugins-backdoored-in-supply-chain-attack"
author: "NewsBot (Validated by Federico Sella)"
description: "多个ShapedPlugin WordPress Pro插件因供应链攻击而遭到入侵，官方版本中被注入了后门代码。"
original_url: "https://thehackernews.com/2026/06/shapedplugin-wordpress-pro-plugins.html"
source: "The Hacker News"
severity: "High"
target: "来自ShapedPlugin的WordPress Pro插件"
cve: null
cvss: null
kev: null
tags: ["news", "cybersecurity"]
news-categories: ["cybersecurity"]
layout: "news"
draft: false
---

多个ShapedPlugin WordPress Pro插件因供应链攻击而遭到入侵，官方版本中被注入了后门代码。

{{< cyber-report severity="High" source="The Hacker News" target="来自ShapedPlugin的WordPress Pro插件" >}}

来自ShapedPlugin的多个WordPress插件在供应链攻击中遭到入侵，未知威胁行为者篡改了官方发布渠道并推送了后门代码。据Wordfence称，攻击者入侵了供应商的构建和分发管道，在通过官方许可更新渠道分发的Pro插件版本中注入了后门代码。

{{< ad-banner >}}

此次攻击凸显了第三方插件生态系统相关的风险，一个供应商被入侵就可能影响众多网站。建议ShapedPlugin Pro插件的用户验证其安装的完整性，并更新到最新的修补版本（如有）。

Wordfence已发布对后门代码的详细分析，可用于检测被入侵的安装。组织应审查其WordPress环境，查找任何未经授权访问或恶意活动的迹象。

{{< netrunner-insight >}}

此次供应链攻击凸显了软件供应链安全控制的迫切需求。SOC分析师应监控异常的插件更新行为，并考虑对所有第三方代码实施完整性检查。DevSecOps团队必须强制执行严格的管道安全和代码签名，以防止类似入侵。

{{< /netrunner-insight >}}

---

**[在 The Hacker News 上阅读全文 ›](https://thehackernews.com/2026/06/shapedplugin-wordpress-pro-plugins.html)**
