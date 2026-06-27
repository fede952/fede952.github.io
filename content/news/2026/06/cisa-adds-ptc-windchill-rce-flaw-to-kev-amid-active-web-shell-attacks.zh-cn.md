---
title: "CISA将PTC Windchill RCE漏洞纳入KEV，活跃Web Shell攻击持续"
date: "2026-06-27T09:25:09Z"
original_date: "2026-06-26T12:31:56"
lang: "zh-cn"
translationKey: "cisa-adds-ptc-windchill-rce-flaw-to-kev-amid-active-web-shell-attacks"
author: "NewsBot (Validated by Federico Sella)"
description: "CISA将PTC Windchill PDMlink和FlexPLM中的一个关键远程代码执行漏洞添加到其已知被利用漏洞目录中，原因是该漏洞正在被积极利用。"
original_url: "https://thehackernews.com/2026/06/cisa-adds-exploited-ptc-windchill-rce.html"
source: "The Hacker News"
severity: "Critical"
target: "PTC Windchill PDMlink and FlexPLM"
cve: null
cvss: null
kev: true
tags: ["news", "cybersecurity"]
news-categories: ["cybersecurity"]
layout: "news"
draft: false
---

CISA将PTC Windchill PDMlink和FlexPLM中的一个关键远程代码执行漏洞添加到其已知被利用漏洞目录中，原因是该漏洞正在被积极利用。

{{< cyber-report severity="Critical" source="The Hacker News" target="PTC Windchill PDMlink and FlexPLM" kev="true" >}}

美国网络安全和基础设施安全局（CISA）已将影响PTC Windchill PDMlink和PTC FlexPLM的一个关键远程代码执行漏洞添加到其已知被利用漏洞（KEV）目录中。该决定基于活跃利用的证据，有报告指出针对这些企业产品数据管理（PDM）和产品生命周期管理（PLM）系统的Web Shell攻击仍在持续。

{{< ad-banner >}}

虽然公告中未披露具体的CVE标识符，但该漏洞被描述为一个关键的RCE漏洞，可能允许攻击者在受影响系统上执行任意代码。使用这些产品的组织被敦促优先进行修补，并检查其环境是否存在受损迹象，因为利用该漏洞可能导致系统完全被接管。

CISA的KEV目录作为联邦机构的约束性操作指令，要求在指定时间范围内进行修复。强烈建议私营部门将此视为高优先级威胁，并实施缓解措施，如网络分段和监控异常的Web Shell活动。

{{< netrunner-insight >}}

对于SOC分析师而言，优先在暴露的Windchill服务器上搜索Web Shell指标——查找应用程序生成的异常子进程或指向未知IP的出站连接。DevSecOps团队应立即应用可用补丁，并在补丁延迟时考虑部署虚拟补丁或WAF规则。这提醒我们，PLM系统在补丁管理中常被忽视，却是勒索软件团伙的有吸引力的目标。

{{< /netrunner-insight >}}

---

**[在 The Hacker News 上阅读全文 ›](https://thehackernews.com/2026/06/cisa-adds-exploited-ptc-windchill-rce.html)**
