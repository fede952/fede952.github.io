---
title: "新型OXLOADER加载器利用恶意谷歌广告传播CastleStealer"
date: "2026-06-23T10:32:59Z"
original_date: "2026-06-22T13:20:12"
lang: "zh-cn"
translationKey: "new-oxloader-loader-uses-malicious-google-ads-to-deliver-castlestealer"
author: "NewsBot (Validated by Federico Sella)"
description: "Elastic Security Labs披露了一场利用恶意谷歌广告分发OXLOADER加载器的攻击活动，该加载器用于投放CastleStealer恶意软件，可能由俄语威胁行为者操控。"
original_url: "https://thehackernews.com/2026/06/new-oxloader-loader-uses-malicious.html"
source: "The Hacker News"
severity: "High"
target: "点击恶意谷歌广告的用户"
cve: null
cvss: null
kev: null
tags: ["news", "cybersecurity"]
news-categories: ["cybersecurity"]
layout: "news"
draft: false
---

Elastic Security Labs披露了一场利用恶意谷歌广告分发OXLOADER加载器的攻击活动，该加载器用于投放CastleStealer恶意软件，可能由俄语威胁行为者操控。

{{< cyber-report severity="High" source="The Hacker News" target="点击恶意谷歌广告的用户" >}}

Elastic Security Labs的网络安全研究人员发现了一场新的攻击活动，该活动利用恶意谷歌广告分发一种此前未报告的恶意软件加载器，名为OXLOADER。该加载器用于向毫无戒心的受害者投放凭证窃取恶意软件CastleStealer。

{{< ad-banner >}}

该活动被认为具有经济动机，可能由俄语威胁行为者操控。使用谷歌广告作为初始感染载体，凸显了网络犯罪分子不断演变的战术，以绕过传统安全措施并触及更广泛的受众。

建议组织和个人在点击广告时保持警惕，即使广告看似来自合法来源。部署广告拦截器并保持安全软件更新，有助于降低此类攻击的风险。

{{< netrunner-insight >}}

对于SOC分析师而言，监控异常的广告点击以及后续与未知域名的网络连接至关重要。DevSecOps团队应考虑在代理过滤器中屏蔽与广告相关的域名，并教育用户即使来自可信搜索引擎的广告也存在点击风险。

{{< /netrunner-insight >}}

---

**[在 The Hacker News 上阅读全文 ›](https://thehackernews.com/2026/06/new-oxloader-loader-uses-malicious.html)**
