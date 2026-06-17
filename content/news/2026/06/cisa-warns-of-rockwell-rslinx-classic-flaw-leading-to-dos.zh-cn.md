---
title: "CISA 警告 Rockwell RSLinx Classic 漏洞可导致拒绝服务"
date: "2026-06-17T11:42:55Z"
original_date: "2026-06-16T12:00:00"
lang: "zh-cn"
translationKey: "cisa-warns-of-rockwell-rslinx-classic-flaw-leading-to-dos"
author: "NewsBot (Validated by Federico Sella)"
description: "CISA 公告强调 CVE-2020-13573，这是 Rockwell Automation RSLinx Classic ≤4.50.00 中的栈缓冲区溢出漏洞，存在拒绝服务和远程代码执行风险。"
original_url: "https://www.cisa.gov/news-events/ics-advisories/icsa-26-167-02"
source: "CISA"
severity: "High"
target: "Rockwell Automation RSLinx Classic"
cve: "CVE-2020-13573"
cvss: 7.5
kev: null
tags: ["news", "cybersecurity"]
news-categories: ["cybersecurity"]
layout: "news"
draft: false
---

CISA 公告强调 CVE-2020-13573，这是 Rockwell Automation RSLinx Classic ≤4.50.00 中的栈缓冲区溢出漏洞，存在拒绝服务和远程代码执行风险。

{{< cyber-report severity="High" source="CISA" target="Rockwell Automation RSLinx Classic" cve="CVE-2020-13573" cvss="7.5" >}}

CISA 发布了一份公告（ICSA-26-167-02），涉及广泛使用的工业通信软件 Rockwell Automation RSLinx Classic 中的一个漏洞。该漏洞被标识为 CVE-2020-13573，是一个栈缓冲区溢出漏洞，可被远程利用以执行任意代码或导致拒绝服务，使应用程序无响应且无法自动恢复。

{{< ad-banner >}}

受影响版本包括 RSLinx Classic 直至 4.50.00 版本。该漏洞的 CVSS v3 评分为 7.5，表明严重性较高。Rockwell Automation 建议升级到 4.60.00 或更高版本，对于无法立即升级的客户，可应用补丁 BF31213。该公告还引用 CWE-125（越界读取）作为根本弱点。

鉴于涉及的关键基础设施领域——关键制造业、能源、食品与农业以及水利与废水处理——以及该产品的全球部署，及时修补至关重要。各组织应优先进行此更新，以降低被利用的风险，尤其是在 RSLinx Classic 暴露于不可信网络的环境中。

{{< netrunner-insight >}}

对于 SOC 分析师，请监控 RSLinx Classic 进程是否出现异常崩溃或无响应，这可能表明存在利用尝试。DevSecOps 团队应立即计划升级到 4.60.00 版本或应用补丁 BF31213，并确保 RSLinx 实例不能直接从互联网访问。鉴于 CVSS 评分和远程代码执行的可能性，请将此视为高优先级修复项。

{{< /netrunner-insight >}}

---

**[在 CISA 上阅读全文 ›](https://www.cisa.gov/news-events/ics-advisories/icsa-26-167-02)**
