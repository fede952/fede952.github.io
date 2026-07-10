---
title: "GigaWiper后门结合磁盘擦除、虚假勒索软件和间谍软件"
date: "2026-07-10T10:21:21Z"
original_date: "2026-07-09T18:08:07"
lang: "zh-cn"
translationKey: "gigawiper-backdoor-combines-disk-wiping-fake-ransomware-and-spyware"
slug: "gigawiper-backdoor-combines-disk-wiping-fake-ransomware-and-spyware"
author: "NewsBot (Validated by Federico Sella)"
description: "微软发现GigaWiper，一种模块化Windows后门，集成了三种破坏性工具：磁盘擦除器、虚假勒索软件和间谍软件，对端点构成严重威胁。"
original_url: "https://thehackernews.com/2026/07/new-gigawiper-windows-backdoor-bundles.html"
source: "The Hacker News"
severity: "High"
target: "Windows端点"
cve: null
cvss: null
kev: null
tags: ["news", "cybersecurity"]
news-categories: ["cybersecurity"]
layout: "news"
draft: false
---

微软发现GigaWiper，一种模块化Windows后门，集成了三种破坏性工具：磁盘擦除器、虚假勒索软件和间谍软件，对端点构成严重威胁。

{{< cyber-report severity="High" source="The Hacker News" target="Windows端点" >}}

微软发现了一种名为GigaWiper的新型破坏性Windows后门，它将三种较旧的恶意程序整合到一个模块化框架中。该后门为操作员提供了一系列可选择的命令，每种命令旨在造成不同类型的损害：完全磁盘擦除、覆盖Windows系统驱动器，或执行使用从未保存的密钥加密文件的虚假勒索软件。

{{< ad-banner >}}

GigaWiper的模块化设计允许攻击者根据目标环境定制其破坏性行为。包含磁盘擦除功能和虚假勒索软件表明，其主要目标是造成最大程度的破坏和数据丢失，而非经济利益。这种技术组合使GigaWiper成为破坏性网络操作中一种多功能且危险的工具。

虽然具体的传播向量尚未披露，但该后门擦除整个磁盘和模拟勒索软件攻击的能力表明其高度复杂性。组织应优先考虑端点检测和响应（EDR）解决方案，并确保强大的备份策略，以减轻此类威胁的影响。

{{< netrunner-insight >}}

对于SOC分析师而言，GigaWiper强调了需要行为检测规则来标记大规模文件操作和磁盘级写入。DevSecOps团队应定期验证备份完整性并测试恢复程序，因为虚假勒索软件可以绕过传统的解密方法。在未经证实的勒索软件事件中，应将其视为潜在的擦除器攻击，直到证明并非如此。

{{< /netrunner-insight >}}

---

**[在 The Hacker News 上阅读全文 ›](https://thehackernews.com/2026/07/new-gigawiper-windows-backdoor-bundles.html)**
