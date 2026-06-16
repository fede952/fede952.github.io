---
title: "DragonForce勒索软件利用Microsoft Teams中继隐藏C2流量"
date: "2026-06-16T12:10:12Z"
original_date: "2026-06-16T10:18:48"
lang: "zh-cn"
translationKey: "dragonforce-ransomware-uses-microsoft-teams-relays-to-hide-c2-traffic"
author: "NewsBot (Validated by Federico Sella)"
description: "DragonForce勒索软件部署自定义恶意软件'Backdoor.Turn'，将命令与控制流量隐藏在Microsoft Teams中继基础设施中。"
original_url: "https://www.bleepingcomputer.com/news/security/ransomware-gang-abuses-microsoft-teams-relays-to-hide-malicious-traffic/"
source: "BleepingComputer"
severity: "High"
target: "Microsoft Teams中继基础设施"
cve: null
cvss: null
kev: null
tags: ["news", "cybersecurity"]
news-categories: ["cybersecurity"]
layout: "news"
draft: false
---

DragonForce勒索软件部署自定义恶意软件'Backdoor.Turn'，将命令与控制流量隐藏在Microsoft Teams中继基础设施中。

{{< cyber-report severity="High" source="BleepingComputer" target="Microsoft Teams中继基础设施" >}}

DragonForce勒索软件组织被观察到使用名为'Backdoor.Turn'的自定义恶意软件，将其命令与控制（C2）流量隐藏在Microsoft Teams中继基础设施中。这种技术使攻击者能够将恶意通信与合法的Teams流量混合，增加了网络防御者的检测难度。

{{< ad-banner >}}

通过滥用Microsoft Teams中继，勒索软件团伙可以绕过可能不会审查到受信任服务流量的传统网络安全控制。该恶意软件可能利用Teams API或协议来隧道传输C2数据，规避基于签名的检测，并允许对受感染网络进行持久访问。

使用Microsoft Teams的组织应监控到Teams端点的异常出站流量模式，并考虑对加密隧道实施额外的检查。此事件突显了勒索软件组织采用离地生存和受信任服务滥用技术以逃避检测的日益增长的趋势。

{{< netrunner-insight >}}

对于SOC分析师而言，这强调了需要建立正常的Teams流量基线，并对异常情况（如意外数据量或连接到非标准Teams端点）发出警报。DevSecOps团队应审查Teams集成权限，并限制不必要的API访问，以减少中继滥用的攻击面。

{{< /netrunner-insight >}}

---

**[在 BleepingComputer 上阅读全文 ›](https://www.bleepingcomputer.com/news/security/ransomware-gang-abuses-microsoft-teams-relays-to-hide-malicious-traffic/)**
