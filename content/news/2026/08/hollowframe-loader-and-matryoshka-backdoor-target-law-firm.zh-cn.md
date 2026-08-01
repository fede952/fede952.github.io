---
title: "HollowFrame加载器和Matryoshka后门瞄准律师事务所"
date: "2026-08-01T09:01:20Z"
original_date: "2026-07-31T16:39:31"
lang: "zh-cn"
translationKey: "hollowframe-loader-and-matryoshka-backdoor-target-law-firm"
slug: "hollowframe-loader-and-matryoshka-backdoor-target-law-firm"
author: "NewsBot (Validated by Federico Sella)"
description: "据Blackpoint Cyber称，新型基于Go的加载器HollowFrame和基于Rust的后门Matryoshka被用于针对一家律师事务所的鱼叉式网络钓鱼攻击。"
original_url: "https://thehackernews.com/2026/07/hollowframe-loader-deploys-matryoshka.html"
source: "The Hacker News"
severity: "High"
target: "律师事务所"
cve: null
cvss: null
kev: null
tags: ["news", "cybersecurity"]
news-categories: ["cybersecurity"]
layout: "news"
draft: false
---

据Blackpoint Cyber称，新型基于Go的加载器HollowFrame和基于Rust的后门Matryoshka被用于针对一家律师事务所的鱼叉式网络钓鱼攻击。

{{< cyber-report severity="High" source="The Hacker News" target="律师事务所" >}}

Blackpoint Cyber发现了一种针对律师事务所的新型攻击链，始于一封鱼叉式网络钓鱼电子邮件，诱使收件人下载一个加密压缩包。该压缩包包含一个Windows快捷方式（LNK）文件，一旦执行，便会启动多阶段感染过程。

{{< ad-banner >}}

该攻击利用了两种此前未被记录的恶意软件家族：HollowFrame（一种基于Go的加载器框架）和Matryoshka（一种基于Rust的后门）。加载器负责传递后门，为攻击者提供对受感染系统的远程访问权限。

此次攻击活动凸显了恶意软件工具的持续演进，攻击者采用Go和Rust等跨平台语言来逃避检测并增加分析难度。在鱼叉式网络钓鱼中使用加密压缩包和LNK文件是一种常见策略，但这些特定工具的组合增加了新的复杂程度。

{{< netrunner-insight >}}

SOC分析师应优先监控LNK文件的执行以及来自电子邮件链接的压缩包下载，因为这些是此攻击链的早期指标。DevSecOps团队应考虑阻止或沙箱化来自加密压缩包的文件的执行，并确保端点检测和响应（EDR）解决方案已调整以检测表现出加载器行为的Go和Rust二进制文件。

{{< /netrunner-insight >}}

---

**[在 The Hacker News 上阅读全文 ›](https://thehackernews.com/2026/07/hollowframe-loader-deploys-matryoshka.html)**
