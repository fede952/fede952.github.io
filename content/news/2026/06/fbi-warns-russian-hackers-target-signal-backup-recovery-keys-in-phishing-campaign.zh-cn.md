---
title: "FBI警告：俄罗斯黑客在钓鱼活动中瞄准Signal备份恢复密钥"
date: "2026-06-28T09:56:23Z"
original_date: "2026-06-26T22:06:17"
lang: "zh-cn"
translationKey: "fbi-warns-russian-hackers-target-signal-backup-recovery-keys-in-phishing-campaign"
author: "NewsBot (Validated by Federico Sella)"
description: "FBI和CISA警告称，与俄罗斯情报机构相关的钓鱼攻击现在窃取Signal备份恢复密钥，使攻击者能够访问受害者的历史消息。"
original_url: "https://www.bleepingcomputer.com/news/security/fbi-russian-hackers-now-target-signal-backup-recovery-keys/"
source: "BleepingComputer"
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

FBI和CISA警告称，与俄罗斯情报机构相关的钓鱼攻击现在窃取Signal备份恢复密钥，使攻击者能够访问受害者的历史消息。

{{< cyber-report severity="High" source="BleepingComputer" target="Signal用户" >}}

FBI和CISA联合发布警告，称一起归因于俄罗斯情报机构的钓鱼活动已演变为针对Signal备份恢复密钥。这些密钥通常用于在新设备上恢复消息历史，一旦被盗，攻击者即可访问受害者的过往对话和联系人。

{{< ad-banner >}}

该活动最初专注于窃取Signal登录凭证，现已扩展至窃取恢复密钥。攻击者利用社会工程策略，例如伪造的Signal群组邀请或安全警报，诱骗用户泄露其恢复密钥。

使用Signal进行敏感通信的组织和个人被敦促启用额外的安全措施，如注册锁定和屏幕锁定，并验证任何恢复密钥或登录凭证请求的真实性。

{{< netrunner-insight >}}

SOC分析师应监控冒充Signal群组邀请或安全警报的钓鱼诱饵，因为这些现在被用于收集恢复密钥。DevSecOps团队应强制执行多因素认证，并教育用户：合法服务绝不会通过未经请求的消息索要恢复密钥或密码。

{{< /netrunner-insight >}}

---

**[在 BleepingComputer 上阅读全文 ›](https://www.bleepingcomputer.com/news/security/fbi-russian-hackers-now-target-signal-backup-recovery-keys/)**
