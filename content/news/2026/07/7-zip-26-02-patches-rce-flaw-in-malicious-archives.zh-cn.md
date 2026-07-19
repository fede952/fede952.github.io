---
title: "7-Zip 26.02 修复恶意压缩包中的远程代码执行漏洞"
date: "2026-07-19T09:02:18Z"
original_date: "2026-07-18T19:32:02"
lang: "zh-cn"
translationKey: "7-zip-26-02-patches-rce-flaw-in-malicious-archives"
slug: "7-zip-26-02-patches-rce-flaw-in-malicious-archives"
author: "NewsBot (Validated by Federico Sella)"
description: "7-Zip 发布了 26.02 版本，修复了一个可通过打开特制压缩文件触发的远程代码执行漏洞。请立即更新。"
original_url: "https://www.bleepingcomputer.com/news/security/update-now-7-zip-fixes-rce-flaw-exploitable-with-malicious-archives/"
source: "BleepingComputer"
severity: "High"
target: "7-Zip 用户"
cve: null
cvss: null
kev: null
tags: ["news", "cybersecurity"]
news-categories: ["cybersecurity"]
layout: "news"
draft: false
---

7-Zip 发布了 26.02 版本，修复了一个可通过打开特制压缩文件触发的远程代码执行漏洞。请立即更新。

{{< cyber-report severity="High" source="BleepingComputer" target="7-Zip 用户" >}}

7-Zip 26.02 版本已发布，用于修复一个远程代码执行漏洞，攻击者可能利用该漏洞在受害者系统上执行任意代码。该漏洞可通过诱骗用户打开特制的压缩文件（例如包含恶意负载的压缩包）来利用。

{{< ad-banner >}}

该漏洞影响该流行文件压缩工具的所有先前版本。虽然公告中未披露 CVE 标识符，但由于可能导致系统完全受损，其严重性被评为高。强烈建议用户立即更新到最新版本。

鉴于 7-Zip 在企业及消费环境中的广泛使用，此补丁对于减少攻击面至关重要。组织应优先通过自动更新机制或手动安装进行部署。

{{< netrunner-insight >}}

SOC 分析师应监控异常的压缩文件活动，并确保所有端点上的 7-Zip 已更新。DevSecOps 团队应将此更新纳入其补丁管理流程，并考虑阻止旧版 7-Zip 访问敏感系统。

{{< /netrunner-insight >}}

---

**[在 BleepingComputer 上阅读全文 ›](https://www.bleepingcomputer.com/news/security/update-now-7-zip-fixes-rce-flaw-exploitable-with-malicious-archives/)**
