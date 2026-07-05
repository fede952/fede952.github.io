---
title: "FortiBleed 攻击者与 Inc、Lynx 勒索软件团伙联手"
date: "2026-07-05T09:38:01Z"
original_date: "2026-07-02T19:11:33"
lang: "zh-cn"
translationKey: "fortibleed-actors-team-up-with-inc-lynx-ransomware-gangs"
slug: "fortibleed-actors-team-up-with-inc-lynx-ransomware-gangs"
author: "NewsBot (Validated by Federico Sella)"
description: "利用 Fortinet 防火墙漏洞和 Nextcloud 零日漏洞的攻击者现在正与勒索软件团伙合作，以将访问权限变现。"
original_url: "https://www.darkreading.com/threat-intelligence/fortibleed-actors-inc-lynx-ransomware-gangs"
source: "Dark Reading"
severity: "High"
target: "Fortinet 防火墙、Nextcloud 服务器"
cve: null
cvss: null
kev: null
tags: ["news", "cybersecurity"]
news-categories: ["cybersecurity"]
layout: "news"
draft: false
---

利用 Fortinet 防火墙漏洞和 Nextcloud 零日漏洞的攻击者现在正与勒索软件团伙合作，以将访问权限变现。

{{< cyber-report severity="High" source="Dark Reading" target="Fortinet 防火墙、Nextcloud 服务器" >}}

FortiBleed 活动背后的威胁行为者通过与 Inc 和 Lynx 勒索软件团伙合作，扩大了其行动范围。在入侵了数千台 Fortinet 防火墙后，他们现在正通过部署勒索软件来变现这些访问权限。

{{< ad-banner >}}

除了 Fortinet 漏洞外，攻击者还在利用 Nextcloud（一款流行的开源文件共享平台）中的零日漏洞。这种双管齐下的方法使他们能够同时针对边界设备和内部协作工具。

与勒索软件团伙的合作表明，他们从初始访问代理转向了全面的勒索行动。使用 Fortinet 或 Nextcloud 产品的组织应优先进行修补，并监控未经授权访问的迹象。

{{< netrunner-insight >}}

这是初始访问代理扩大规模的典型案例。SOC 团队应搜寻异常的 Fortinet VPN 连接和 Nextcloud 登录异常。如果您的环境中存在 FortiGate 或 Nextcloud，请假设已被入侵，并立即进行取证审查。

{{< /netrunner-insight >}}

---

**[在 Dark Reading 上阅读全文 ›](https://www.darkreading.com/threat-intelligence/fortibleed-actors-inc-lynx-ransomware-gangs)**
