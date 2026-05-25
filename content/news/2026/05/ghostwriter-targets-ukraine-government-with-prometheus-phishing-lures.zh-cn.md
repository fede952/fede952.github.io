---
title: "Ghostwriter以Prometheus钓鱼诱饵攻击乌克兰政府"
date: "2026-05-25T11:07:58Z"
original_date: "2026-05-22T16:20:32"
lang: "zh-cn"
translationKey: "ghostwriter-targets-ukraine-government-with-prometheus-phishing-lures"
author: "NewsBot (Validated by Federico Sella)"
description: "与白俄罗斯结盟的威胁行为者Ghostwriter利用Prometheus主题的钓鱼邮件，通过被攻陷的账户部署恶意软件，针对乌克兰政府实体。"
original_url: "https://thehackernews.com/2026/05/ghostwriter-targets-ukraine-government.html"
source: "The Hacker News"
severity: "High"
target: "乌克兰政府实体"
cve: null
cvss: null
kev: null
tags: ["news", "cybersecurity"]
news-categories: ["cybersecurity"]
layout: "news"
draft: false
---

与白俄罗斯结盟的威胁行为者Ghostwriter利用Prometheus主题的钓鱼邮件，通过被攻陷的账户部署恶意软件，针对乌克兰政府实体。

{{< cyber-report severity="High" source="The Hacker News" target="乌克兰政府实体" >}}

与白俄罗斯结盟的威胁行为者Ghostwriter（又名UAC-0057和UNC1151）被观察到利用与乌克兰在线学习平台Prometheus相关的诱饵，向乌克兰政府组织发送钓鱼邮件。乌克兰计算机应急响应小组（CERT-UA）报告称，这些攻击涉及从被攻陷的账户向政府实体发送恶意邮件。

{{< ad-banner >}}

这些钓鱼邮件旨在传递Prometheus主题的恶意软件，可能作为间谍活动或破坏活动的初始访问向量。Ghostwriter历史上曾与支持白俄罗斯利益的信息操作和网络间谍活动有关，此次行动延续了其在持续冲突中针对乌克兰目标的重点。

乌克兰的组织，特别是政府机构，应警惕提及Prometheus或其他教育平台的钓鱼邮件。CERT-UA建议验证发件人身份，避免点击来自不可信来源的链接或打开附件。实施多因素认证并监控异常账户活动有助于降低被攻陷的风险。

{{< netrunner-insight >}}

此次行动凸显了电子邮件安全控制的重要性，尤其是对于冲突地区的政府实体。SOC分析师应优先监控提及本地平台（如Prometheus）的钓鱼诱饵，DevSecOps团队应强制执行严格的电子邮件认证（DMARC、DKIM、SPF）以减少欺骗风险。此外，被攻陷账户作为初始向量，强调了快速事件响应和凭证轮换的必要性。

{{< /netrunner-insight >}}

---

**[在 The Hacker News 上阅读全文 ›](https://thehackernews.com/2026/05/ghostwriter-targets-ukraine-government.html)**
