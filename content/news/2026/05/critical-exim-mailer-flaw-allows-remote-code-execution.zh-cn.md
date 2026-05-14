---
title: "关键Exim邮件服务器漏洞可致远程代码执行"
date: "2026-05-14T09:33:22Z"
original_date: "2026-05-13T20:23:50"
lang: "zh-cn"
translationKey: "critical-exim-mailer-flaw-allows-remote-code-execution"
author: "NewsBot (Validated by Federico Sella)"
description: "Exim邮件传输代理配置中的严重漏洞可能允许未经身份验证的攻击者远程执行任意代码。请立即修补。"
original_url: "https://www.bleepingcomputer.com/news/security/new-critical-exim-mailer-flaw-allows-remote-code-execution/"
source: "BleepingComputer"
severity: "Critical"
target: "Exim邮件传输代理"
cve: null
cvss: null
kev: null
tags: ["news", "cybersecurity"]
news-categories: ["cybersecurity"]
layout: "news"
draft: false
---

Exim邮件传输代理配置中的严重漏洞可能允许未经身份验证的攻击者远程执行任意代码。请立即修补。

{{< cyber-report severity="Critical" source="BleepingComputer" target="Exim邮件传输代理" >}}

在Exim开源邮件传输代理中发现了一个影响特定配置的严重漏洞。该漏洞可能允许未经身份验证的远程攻击者在易受攻击的系统上执行任意代码。

{{< ad-banner >}}

Exim广泛用作Unix类系统上的邮件服务器，这使得该漏洞对于依赖其进行邮件传递的组织尤其令人担忧。漏洞利用的具体技术细节尚未完全披露，但严重等级表明建议立即修补。

管理员应检查其Exim配置，并应用Exim项目提供的任何可用更新。在部署补丁之前，请考虑实施网络级访问控制以限制对易受攻击服务的暴露。

{{< netrunner-insight >}}

这是一个广泛部署的MTA中的关键远程代码执行向量。SOC分析师应优先扫描Exim实例并验证配置加固。DevSecOps团队必须加快修补速度，并考虑使用WAF规则阻止利用尝试，直到更新应用完毕。

{{< /netrunner-insight >}}

---

**[在 BleepingComputer 上阅读全文 ›](https://www.bleepingcomputer.com/news/security/new-critical-exim-mailer-flaw-allows-remote-code-execution/)**
