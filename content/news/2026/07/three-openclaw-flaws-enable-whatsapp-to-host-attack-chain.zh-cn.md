---
title: "三个OpenClaw漏洞可构建WhatsApp到主机的攻击链"
date: "2026-07-11T08:46:01Z"
original_date: "2026-07-10T14:19:50"
lang: "zh-cn"
translationKey: "three-openclaw-flaws-enable-whatsapp-to-host-attack-chain"
slug: "three-openclaw-flaws-enable-whatsapp-to-host-attack-chain"
author: "NewsBot (Validated by Federico Sella)"
description: "研究人员详细介绍了OpenClaw的三个高严重性漏洞，这些漏洞可能导致凭证窃取、权限提升以及在主机上执行代码。"
original_url: "https://thehackernews.com/2026/07/researcher-details-whatsapp-to-host.html"
source: "The Hacker News"
severity: "High"
target: "OpenClaw AI助手"
cve: null
cvss: 8.8
kev: null
tags: ["news", "cybersecurity"]
news-categories: ["cybersecurity"]
layout: "news"
draft: false
---

研究人员详细介绍了OpenClaw的三个高严重性漏洞，这些漏洞可能导致凭证窃取、权限提升以及在主机上执行代码。

{{< cyber-report severity="High" source="The Hacker News" target="OpenClaw AI助手" cvss="8.8" >}}

现已披露OpenClaw个人AI助手中三个已修补的安全漏洞细节，若成功利用，可在主机上实现凭证窃取、权限提升和任意代码执行。这些漏洞由一名研究人员公开，他概述了一条从WhatsApp消息开始的攻击链。

{{< ad-banner >}}

其中一个漏洞编号为GHSA-hjr6-g723-hmfm，CVSS评分为8.8，被描述为高严重性。另外两个漏洞的具体性质尚未完全公开，但它们共同对将OpenClaw与WhatsApp等消息平台集成的用户构成重大风险。

该攻击链利用了AI助手处理消息的能力，可能允许攻击者提升权限并在主机系统上执行任意代码。建议用户应用最新补丁以缓解这些风险。

{{< netrunner-insight >}}

此攻击链凸显了将AI助手与消息平台集成的风险。SOC分析师应监控源自AI助手组件的异常进程执行，而DevSecOps团队必须确保此类集成被沙箱化并及时打补丁。

{{< /netrunner-insight >}}

---

**[在 The Hacker News 上阅读全文 ›](https://thehackernews.com/2026/07/researcher-details-whatsapp-to-host.html)**
