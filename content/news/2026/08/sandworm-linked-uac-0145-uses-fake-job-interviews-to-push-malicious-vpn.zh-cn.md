---
title: "与Sandworm关联的UAC-0145利用虚假求职面试推送恶意VPN"
date: "2026-08-15T07:23:49Z"
original_date: "2026-08-11T18:36:47"
lang: "zh-cn"
translationKey: "sandworm-linked-uac-0145-uses-fake-job-interviews-to-push-malicious-vpn"
slug: "sandworm-linked-uac-0145-uses-fake-job-interviews-to-push-malicious-vpn"
author: "NewsBot (Validated by Federico Sella)"
description: "CERT-UA警告称，俄罗斯国家支持的黑客组织通过虚假求职面试针对乌克兰IT工作者，并交付可执行命令的VPN。"
original_url: "https://thehackernews.com/2026/08/sandworm-linked-uac-0145-uses-fake-job.html"
source: "The Hacker News"
severity: "High"
target: "乌克兰IT工作者"
cve: null
cvss: null
kev: null
tags: ["news", "cybersecurity"]
news-categories: ["cybersecurity"]
layout: "news"
draft: false
---

CERT-UA警告称，俄罗斯国家支持的黑客组织通过虚假求职面试针对乌克兰IT工作者，并交付可执行命令的VPN。

{{< cyber-report severity="High" source="The Hacker News" target="乌克兰IT工作者" >}}

CERT-UA披露了一项新的社会工程攻击活动，该活动归因于威胁集群UAC-0145，这是俄罗斯国家支持的组织Sandworm（APT44）的一个子组织。该活动通过冒充招聘人员并引诱受害者参加虚假求职面试，针对乌克兰的IT工作者。

{{< ad-banner >}}

在面试过程中，受害者被诱骗安装一个VPN应用程序，该应用程序实际上是能够执行任意命令的恶意软件。这种技术利用与招聘相关的信任来绕过用户防御。

这一活动凸显了俄罗斯国家支持的行为者对乌克兰组织，特别是IT领域的组织构成的持续网络威胁。CERT-UA将此事归因于UAC-0145，突显了这些攻击的复杂性和持久性。

{{< netrunner-insight >}}

该活动展示了社会工程在传递恶意软件方面的有效性，即使对安全意识强的IT专业人士也是如此。SOC分析师应教育用户警惕此类基于招聘的诱饵，并监控异常的VPN安装或命令执行。DevSecOps团队应实施应用程序白名单，并限制未签名二进制文件的执行，以缓解此类威胁。

{{< /netrunner-insight >}}

---

**[在 The Hacker News 上阅读全文 ›](https://thehackernews.com/2026/08/sandworm-linked-uac-0145-uses-fake-job.html)**
