---
title: "CISA 要求紧急修复遭主动攻击的 Cisco UC Manager 漏洞"
date: "2026-06-27T09:26:21Z"
original_date: "2026-06-26T19:43:06"
lang: "zh-cn"
translationKey: "cisa-orders-urgent-patch-for-cisco-uc-manager-flaw-under-active-attack"
author: "NewsBot (Validated by Federico Sella)"
description: "联邦机构必须在周日之前修补 Cisco Unified Communications Manager 漏洞，CISA 警告称该漏洞正被积极利用。"
original_url: "https://www.bleepingcomputer.com/news/security/cisa-sets-urgent-deadline-to-fix-cisco-flaw-exploited-in-attacks/"
source: "BleepingComputer"
severity: "High"
target: "Cisco Unified Communications Manager Server"
cve: null
cvss: null
kev: null
tags: ["news", "cybersecurity"]
news-categories: ["cybersecurity"]
layout: "news"
draft: false
---

联邦机构必须在周日之前修补 Cisco Unified Communications Manager 漏洞，CISA 警告称该漏洞正被积极利用。

{{< cyber-report severity="High" source="BleepingComputer" target="Cisco Unified Communications Manager Server" >}}

美国网络安全与基础设施安全局（CISA）发布紧急指令，要求联邦机构在周日之前修补 Cisco Unified Communications Manager Server 中的漏洞。该漏洞据报正在攻击中被积极利用，但现有信息中未披露具体的 CVE 标识符或技术细节。

{{< ad-banner >}}

Cisco Unified Communications Manager 是企业语音和视频通信的关键组件，因此成为威胁行为者的高价值目标。短暂的修复时间表凸显了威胁的严重性以及跨受影响系统快速打补丁的必要性。

强烈建议联邦政府以外的组织也优先修补此漏洞。鉴于漏洞已被积极利用，延迟缓解措施可能导致网络受损、数据泄露或受影响环境内的进一步横向移动。

{{< netrunner-insight >}}

对于 SOC 分析师，请立即检查您的环境中是否存在任何 Cisco UC Manager 实例，并验证补丁状态。DevSecOps 团队应将其视为 P1 事件并加速修补，因为 CISA 的截止日期表明威胁行为者活跃。修补后监控异常的 SIP 流量或身份验证异常。

{{< /netrunner-insight >}}

---

**[在 BleepingComputer 上阅读全文 ›](https://www.bleepingcomputer.com/news/security/cisa-sets-urgent-deadline-to-fix-cisco-flaw-exploited-in-attacks/)**
