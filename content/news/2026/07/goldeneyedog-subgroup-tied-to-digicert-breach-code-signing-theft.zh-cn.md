---
title: "GoldenEyeDog子组织与DigiCert入侵及代码签名盗窃事件关联"
date: "2026-07-18T08:46:42Z"
original_date: "2026-07-17T16:39:16"
lang: "zh-cn"
translationKey: "goldeneyedog-subgroup-tied-to-digicert-breach-code-signing-theft"
slug: "goldeneyedog-subgroup-tied-to-digicert-breach-code-signing-theft"
author: "NewsBot (Validated by Federico Sella)"
description: "研究人员将2026年4月DigiCert安全事件归因于CylindricalCanine，这是中国网络犯罪组织GoldenEyeDog的一个子组织，以针对赌博和游戏行业而闻名。"
original_url: "https://thehackernews.com/2026/07/goldeneyedog-subgroup-linked-to.html"
source: "The Hacker News"
severity: "High"
target: "DigiCert代码签名基础设施"
cve: null
cvss: null
kev: null
tags: ["news", "cybersecurity"]
news-categories: ["cybersecurity"]
layout: "news"
draft: false
---

研究人员将2026年4月DigiCert安全事件归因于CylindricalCanine，这是中国网络犯罪组织GoldenEyeDog的一个子组织，以针对赌博和游戏行业而闻名。

{{< cyber-report severity="High" source="The Hacker News" target="DigiCert代码签名基础设施" >}}

网络安全研究人员已将2026年4月DigiCert安全事件归因于一个名为CylindricalCanine的威胁活动集群。该组织被描述为GoldenEyeDog（也称为APT-Q-27、Dragon Breath和Miuuti Group）的一个子组织，GoldenEyeDog是一个历史上针对赌博和游戏行业的中国网络犯罪组织。

{{< ad-banner >}}

此次入侵涉及代码签名证书的盗窃，这可能使威胁行为者能够使用合法凭证签署恶意软件，从而绕过安全控制。Expel分享了该事件的技术细节，强调了此次行动的高度复杂性。

依赖DigiCert颁发证书的组织应审查其证书清单，并监控任何未经授权的使用。该事件凸显了针对受信任证书颁发机构的供应链攻击所带来的风险。

{{< netrunner-insight >}}

对于SOC分析师：优先监控代码签名异常和意外的证书使用。DevSecOps团队应实施严格的证书生命周期管理，并考虑使用短期证书以限制盗窃造成的暴露。

{{< /netrunner-insight >}}

---

**[在 The Hacker News 上阅读全文 ›](https://thehackernews.com/2026/07/goldeneyedog-subgroup-linked-to.html)**
