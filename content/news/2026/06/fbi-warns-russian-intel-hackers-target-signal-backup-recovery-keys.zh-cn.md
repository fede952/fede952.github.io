---
title: "FBI警告：俄罗斯情报黑客瞄准Signal备份恢复密钥"
date: "2026-06-28T09:57:31Z"
original_date: "2026-06-26T19:38:29"
lang: "zh-cn"
translationKey: "fbi-warns-russian-intel-hackers-target-signal-backup-recovery-keys"
author: "NewsBot (Validated by Federico Sella)"
description: "FBI和CISA更新警告：俄罗斯情报钓鱼攻击现窃取Signal备份恢复密钥，以读取私密消息并接管账户。"
original_url: "https://thehackernews.com/2026/06/fbi-warns-russian-intelligence-hackers.html"
source: "The Hacker News"
severity: "High"
target: "Signal用户"
cve: null
cvss: null
kev: null
tags: ["news", "cybersecurity"]
news-categories: ["cybersecurity"]
layout: "news"
draft: false
---

FBI和CISA更新警告：俄罗斯情报钓鱼攻击现窃取Signal备份恢复密钥，以读取私密消息并接管账户。

{{< cyber-report severity="High" source="The Hacker News" target="Signal用户" >}}

FBI和CISA已更新其3月份关于俄罗斯情报钓鱼活动针对Signal账户的警告。攻击者新增了一个步骤：他们诱骗目标交出Signal备份恢复密钥。一旦获得该密钥，攻击者可以恢复账户备份，读取私密和群组消息历史，并完全接管账户。

{{< ad-banner >}}

该密钥即使在初始入侵后仍然有效，从而实现持久访问。这种技术绕过了传统的双因素认证，因为恢复密钥本用于合法账户恢复。建议强调用户绝不应分享其恢复密钥，并应启用注册锁定和其他安全功能。

组织应教育用户了解这一特定的钓鱼向量，并考虑对敏感通信实施额外的验证步骤。该威胁归因于俄罗斯情报行为者，突显了该活动的地缘政治背景。

{{< netrunner-insight >}}

这是一个针对安全功能的社会工程学典型例子。SOC分析师应监控异常的账户恢复请求，并教育用户绝不可分享Signal的备份恢复密钥。DevSecOps团队应考虑为关键通信集成抗钓鱼认证。

{{< /netrunner-insight >}}

---

**[在 The Hacker News 上阅读全文 ›](https://thehackernews.com/2026/06/fbi-warns-russian-intelligence-hackers.html)**
