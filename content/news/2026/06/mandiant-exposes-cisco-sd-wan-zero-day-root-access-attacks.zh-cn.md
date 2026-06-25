---
title: "Mandiant曝光Cisco SD-WAN零日漏洞导致root权限被攻击"
date: "2026-06-25T10:15:15Z"
original_date: "2026-06-24T21:29:10"
lang: "zh-cn"
translationKey: "mandiant-exposes-cisco-sd-wan-zero-day-root-access-attacks"
author: "NewsBot (Validated by Federico Sella)"
description: "新细节揭示了黑客如何利用CVE-2026-20245零日漏洞，在Cisco Catalyst SD-WAN设备上创建恶意root账户。"
original_url: "https://www.bleepingcomputer.com/news/security/mandiant-reveals-how-cisco-sd-wan-zero-day-attacks-gained-root-access/"
source: "BleepingComputer"
severity: "High"
target: "Cisco Catalyst SD-WAN设备"
cve: "CVE-2026-20245"
cvss: null
kev: null
tags: ["news", "cybersecurity"]
news-categories: ["cybersecurity"]
layout: "news"
draft: false
---

新细节揭示了黑客如何利用CVE-2026-20245零日漏洞，在Cisco Catalyst SD-WAN设备上创建恶意root账户。

{{< cyber-report severity="High" source="BleepingComputer" target="Cisco Catalyst SD-WAN设备" cve="CVE-2026-20245" >}}

Mandiant披露了关于威胁行为者如何利用Cisco Catalyst SD-WAN软件中的零日漏洞（编号CVE-2026-20245）获取目标设备root权限的新技术细节。攻击涉及创建恶意root账户，从而实现持久的未授权访问。

{{< ad-banner >}}

该漏洞已在Cisco最近的安全公告中得到修复，曾被用于有限的目标攻击。Mandiant的分析揭示了具体的利用链，强调了及时应用安全更新的重要性。

使用Cisco SD-WAN解决方案的组织被敦促审计其系统是否存在入侵迹象，例如未授权账户或异常的root级别活动。此事件凸显了强大的补丁管理和网络基础设施监控的迫切需求。

{{< netrunner-insight >}}

对于SOC分析师，优先监控Cisco SD-WAN设备上的未授权账户创建和权限提升事件。DevSecOps团队应确保快速部署Cisco的安全补丁，并考虑对SD-WAN管理接口进行分段，以减少攻击面。

{{< /netrunner-insight >}}

---

**[在 BleepingComputer 上阅读全文 ›](https://www.bleepingcomputer.com/news/security/mandiant-reveals-how-cisco-sd-wan-zero-day-attacks-gained-root-access/)**
