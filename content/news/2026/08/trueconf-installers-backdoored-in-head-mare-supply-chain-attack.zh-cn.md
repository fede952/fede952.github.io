---
title: "TrueConf 安装程序在 Head Mare 供应链攻击中被植入后门"
date: "2026-08-09T07:48:35Z"
original_date: "2026-08-08T14:16:23"
lang: "zh-cn"
translationKey: "trueconf-installers-backdoored-in-head-mare-supply-chain-attack"
slug: "trueconf-installers-backdoored-in-head-mare-supply-chain-attack"
author: "NewsBot (Validated by Federico Sella)"
description: "Head Mare 利用未修补的 TrueConf 服务器，将客户端安装程序替换为带后门的版本，向受害者分发恶意软件。"
original_url: "https://www.bleepingcomputer.com/news/security/hackers-breach-trueconf-to-trojanize-client-installers-with-backdoors/"
source: "BleepingComputer"
severity: "High"
target: "TrueConf 视频会议服务器"
cve: null
cvss: null
kev: null
tags: ["news", "cybersecurity"]
news-categories: ["cybersecurity"]
layout: "news"
draft: false
---

Head Mare 利用未修补的 TrueConf 服务器，将客户端安装程序替换为带后门的版本，向受害者分发恶意软件。

{{< cyber-report severity="High" source="BleepingComputer" target="TrueConf 视频会议服务器" >}}

黑客行动主义组织 Head Mare 一直在积极利用未修补的 TrueConf 视频会议服务器中的漏洞。通过入侵这些服务器，攻击者能够将合法的客户端安装程序替换为包含后门的恶意版本。

{{< ad-banner >}}

当用户下载并执行被木马化的安装程序时，后门会被部署到他们的系统中，可能使攻击者获得远程访问和控制权。这种供应链式攻击利用了用户对官方软件分发渠道的信任。

使用 TrueConf 的组织应立即验证其安装程序的完整性，并确保所有服务器已修补已知漏洞。此次攻击凸显了监控软件分发中的异常行为以及保持稳健的补丁管理实践的重要性。

{{< netrunner-insight >}}

此事件强调了供应链警惕性的必要性：始终验证下载的安装程序的校验和和签名，即使来自官方来源。对于 SOC 团队，请监控安装后异常的出站网络连接或进程，这些可能表明后门已被激活。补丁管理至关重要——未修补的服务器是攻击者的唾手可得的目标。

{{< /netrunner-insight >}}

---

**[在 BleepingComputer 上阅读全文 ›](https://www.bleepingcomputer.com/news/security/hackers-breach-trueconf-to-trojanize-client-installers-with-backdoors/)**
