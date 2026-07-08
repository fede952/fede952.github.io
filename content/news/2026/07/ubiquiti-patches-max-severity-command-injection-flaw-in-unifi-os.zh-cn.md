---
title: "Ubiquiti 修复 UniFi OS 中最高严重级别的命令注入漏洞"
date: "2026-07-08T09:24:49Z"
original_date: "2026-07-08T08:15:20"
lang: "zh-cn"
translationKey: "ubiquiti-patches-max-severity-command-injection-flaw-in-unifi-os"
slug: "ubiquiti-patches-max-severity-command-injection-flaw-in-unifi-os"
author: "NewsBot (Validated by Federico Sella)"
description: "Ubiquiti 发布了针对 UniFi OS 中七个严重漏洞的安全更新，其中包括一个最高严重级别的命令注入漏洞。管理员被敦促立即修补。"
original_url: "https://www.bleepingcomputer.com/news/security/ubiquiti-warns-of-new-max-severity-unifi-os-vulnerability/"
source: "BleepingComputer"
severity: "Critical"
target: "UniFi OS"
cve: null
cvss: null
kev: null
tags: ["news", "cybersecurity"]
news-categories: ["cybersecurity"]
layout: "news"
draft: false
---

Ubiquiti 发布了针对 UniFi OS 中七个严重漏洞的安全更新，其中包括一个最高严重级别的命令注入漏洞。管理员被敦促立即修补。

{{< cyber-report severity="Critical" source="BleepingComputer" target="UniFi OS" >}}

Ubiquiti 已发布安全更新，以解决其 UniFi OS（为其网络设备提供支持的操作系统）中的七个严重漏洞。其中最严重的是一个最高严重级别的漏洞，可在命令注入攻击中被利用，可能允许攻击者在受影响的系统上执行任意命令。

{{< ad-banner >}}

这些漏洞影响运行 UniFi OS 的多种 Ubiquiti 产品。虽然初始公告中未披露具体的 CVE 标识符，但该公司已敦促所有用户立即应用最新的固件更新，以降低被利用的风险。

鉴于这些漏洞的严重性，特别是命令注入漏洞，使用 Ubiquiti 设备的组织应优先进行修补。目前尚未报告有主动利用的证据，但严重性值得安全团队立即关注。

{{< netrunner-insight >}}

对于任何运行 Ubiquiti UniFi 设备的组织来说，这是一个必须修补的情况。网络基础设施中的命令注入漏洞是红队的梦想，因此预计概念验证漏洞利用会很快出现。优先进行修补，并监控受影响设备的异常出站连接。

{{< /netrunner-insight >}}

---

**[在 BleepingComputer 上阅读全文 ›](https://www.bleepingcomputer.com/news/security/ubiquiti-warns-of-new-max-severity-unifi-os-vulnerability/)**
