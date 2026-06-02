---
title: "SideCopy 以 Xeno RAT 攻击阿富汗财政部"
date: "2026-06-02T11:14:31Z"
original_date: "2026-06-02T09:05:40"
lang: "zh-cn"
translationKey: "sidecopy-targets-afghanistan-finance-ministry-with-xeno-rat"
author: "NewsBot (Validated by Federico Sella)"
description: "与巴基斯坦关联的 SideCopy 组织使用带有普什图语 LNK 文件的鱼叉式钓鱼攻击，向阿富汗财政部投递 Xeno RAT。"
original_url: "https://thehackernews.com/2026/06/pakistan-linked-sidecopy-targets.html"
source: "The Hacker News"
severity: "High"
target: "阿富汗财政部"
cve: null
cvss: null
kev: null
tags: ["news", "cybersecurity"]
news-categories: ["cybersecurity"]
layout: "news"
draft: false
---

与巴基斯坦关联的 SideCopy 组织使用带有普什图语 LNK 文件的鱼叉式钓鱼攻击，向阿富汗财政部投递 Xeno RAT。

{{< cyber-report severity="High" source="The Hacker News" target="阿富汗财政部" >}}

网络安全研究人员披露了一场很可能由与巴基斯坦结盟的 SideCopy 组织发起的鱼叉式钓鱼攻击，目标为阿富汗财政部。攻击始于一个包含恶意 LNK 文件的 ZIP 压缩包，该文件使用精心构造的普什图语文件名来诱骗受害者。

{{< ad-banner >}}

所投递的有效载荷是 Xeno RAT，一种开源远程访问木马。该工具为攻击者提供了对受感染系统的广泛控制，能够窃取数据并进一步入侵网络。使用普什图语表明攻击针对阿富汗境内的本地目标。

SideCopy 历来与巴基斯坦威胁行为者有关联，并曾以东南亚实体为目标。此次攻击凸显了该地区持续的地缘政治网络间谍活动，政府部门成为情报收集的主要目标。

{{< netrunner-insight >}}

SOC 分析师应监控鱼叉式钓鱼邮件中带有普什图语文件名的 LNK 文件和 ZIP 压缩包。DevSecOps 团队应强制执行严格的邮件附件过滤和用户安全意识培训，特别是对于与阿富汗或南亚事务相关的组织。Xeno RAT 的开源特性意味着检测签名可用，请确保您的 EDR 解决方案已更新。

{{< /netrunner-insight >}}

---

**[在 The Hacker News 上阅读全文 ›](https://thehackernews.com/2026/06/pakistan-linked-sidecopy-targets.html)**
