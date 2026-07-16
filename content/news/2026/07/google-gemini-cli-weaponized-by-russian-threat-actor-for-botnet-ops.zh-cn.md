---
title: "俄罗斯威胁行为者将Google Gemini CLI武器化用于僵尸网络操作"
date: "2026-07-16T09:08:49Z"
original_date: "2026-07-15T18:33:48"
lang: "zh-cn"
translationKey: "google-gemini-cli-weaponized-by-russian-threat-actor-for-botnet-ops"
slug: "google-gemini-cli-weaponized-by-russian-threat-actor-for-botnet-ops"
author: "NewsBot (Validated by Federico Sella)"
description: "一名被称为'bandcampro'的俄语威胁行为者滥用了Google的开源Gemini CLI AI工具来操作僵尸网络并作为黑客代理。"
original_url: "https://www.bleepingcomputer.com/news/security/google-gemini-cli-abused-as-a-hacking-agent-malware-botnet-operator/"
source: "BleepingComputer"
severity: "Medium"
target: "Gemini CLI用户"
cve: null
cvss: null
kev: null
tags: ["news", "cybersecurity"]
news-categories: ["cybersecurity"]
layout: "news"
draft: false
---

一名被称为'bandcampro'的俄语威胁行为者滥用了Google的开源Gemini CLI AI工具来操作僵尸网络并作为黑客代理。

{{< cyber-report severity="Medium" source="BleepingComputer" target="Gemini CLI用户" >}}

一名被称为'bandcampro'的俄语威胁行为者被观察到滥用Google的开源Gemini CLI AI工具来操作一个小型僵尸网络并作为黑客代理。该行为者利用该工具的功能自动化恶意活动，包括命令执行和数据窃取，有效地将合法的AI助手变成了网络武器。

{{< ad-banner >}}

对Gemini CLI的滥用凸显了一种日益增长的趋势，即威胁行为者将合法的AI工具重新用于恶意目的。通过将CLI集成到其僵尸网络基础设施中，该行为者能够扩大操作规模同时规避检测，因为该工具的流量可能与正常的AI API使用混在一起。

这一事件强调了组织需要监控其环境中AI工具的使用并实施严格的访问控制。安全团队应以与远程访问工具相同的审查标准对待AI CLI工具，因为它们的自动化能力可能被利用来加速攻击。

{{< netrunner-insight >}}

对于SOC分析师来说，此案例提醒要监控AI CLI工具的异常使用，尤其是那些具有网络访问权限的工具。DevSecOps工程师应考虑对这类工具进行沙箱化或限制，以防止其在自动化攻击中被滥用。有益的自动化和恶意的自动化之间界限很薄——将AI CLI视为潜在的攻击向量。

{{< /netrunner-insight >}}

---

**[在 BleepingComputer 上阅读全文 ›](https://www.bleepingcomputer.com/news/security/google-gemini-cli-abused-as-a-hacking-agent-malware-botnet-operator/)**
