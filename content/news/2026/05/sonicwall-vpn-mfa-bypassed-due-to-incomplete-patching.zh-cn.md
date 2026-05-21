---
title: "SonicWall VPN MFA因补丁不完整被绕过"
date: "2026-05-21T10:35:14Z"
original_date: "2026-05-20T21:19:17"
lang: "zh-cn"
translationKey: "sonicwall-vpn-mfa-bypassed-due-to-incomplete-patching"
author: "NewsBot (Validated by Federico Sella)"
description: "威胁行为者对未打补丁的SonicWall Gen6 SSL-VPN设备进行暴力破解VPN凭证并绕过MFA，部署勒索软件工具。"
original_url: "https://www.bleepingcomputer.com/news/security/hackers-bypass-sonicwall-vpn-mfa-due-to-incomplete-patching/"
source: "BleepingComputer"
severity: "High"
target: "SonicWall Gen6 SSL-VPN设备"
cve: null
cvss: null
kev: null
tags: ["news", "cybersecurity"]
news-categories: ["cybersecurity"]
layout: "news"
draft: false
---

威胁行为者对未打补丁的SonicWall Gen6 SSL-VPN设备进行暴力破解VPN凭证并绕过MFA，部署勒索软件工具。

{{< cyber-report severity="High" source="BleepingComputer" target="SonicWall Gen6 SSL-VPN设备" >}}

已观察到威胁行为者对SonicWall Gen6 SSL-VPN设备进行暴力破解VPN凭证并绕过多因素认证（MFA）。这些攻击利用不完整的补丁，使攻击者能够部署常用于勒索软件操作的工具。

{{< ad-banner >}}

该漏洞使攻击者能够在攻破VPN凭证后未经授权访问内部网络。一旦进入，他们可以横向移动并部署勒索软件载荷，对依赖这些设备进行远程访问的组织构成重大风险。

SonicWall已发布补丁解决此问题，但这些更新的不完整应用使系统暴露在风险中。敦促组织验证所有推荐的补丁是否已完全安装，并监控未经授权的VPN访问迹象。

{{< netrunner-insight >}}

此事件凸显了彻底补丁管理的至关重要性。SOC分析师应优先验证所有SonicWall Gen6设备是否拥有最新固件，并监控VPN日志中的异常认证模式。DevSecOps团队应考虑实施额外的MFA层和网络分段以缓解此类绕过。

{{< /netrunner-insight >}}

---

**[在 BleepingComputer 上阅读全文 ›](https://www.bleepingcomputer.com/news/security/hackers-bypass-sonicwall-vpn-mfa-due-to-incomplete-patching/)**
