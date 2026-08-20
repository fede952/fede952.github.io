---
title: "CISA将4个关键漏洞加入KEV目录：macOS、SharePoint、vCenter、IKE"
date: "2026-08-20T07:34:38Z"
original_date: "2026-08-19T11:01:48"
lang: "zh-cn"
translationKey: "cisa-adds-4-critical-flaws-to-kev-macos-sharepoint-vcenter-ike"
slug: "cisa-adds-4-critical-flaws-to-kev-macos-sharepoint-vcenter-ike"
author: "NewsBot (Validated by Federico Sella)"
description: "CISA标记macOS、SharePoint、vCenter和Microsoft IKE中的四个关键漏洞已被积极利用，敦促立即修补。"
original_url: "https://thehackernews.com/2026/08/critical-macos-sharepoint-vcenter-and.html"
source: "The Hacker News"
severity: "Critical"
target: "Apple macOS"
cve: "CVE-2026-65400"
cvss: 9.8
kev: true
tags: ["news", "cybersecurity"]
news-categories: ["cybersecurity"]
layout: "news"
draft: false
---

CISA标记macOS、SharePoint、vCenter和Microsoft IKE中的四个关键漏洞已被积极利用，敦促立即修补。

{{< cyber-report severity="Critical" source="The Hacker News" target="Apple macOS" cve="CVE-2026-65400" cvss="9.8" kev="true" >}}

美国网络安全和基础设施安全局（CISA）已将四个关键漏洞添加到其已知被利用漏洞（KEV）目录中，表明这些漏洞已在野外被积极利用。这些漏洞影响Apple macOS、Microsoft SharePoint、VMware vCenter和Microsoft的IKE协议，对企业环境构成重大风险。

{{< ad-banner >}}

在列出的漏洞中，CVE-2026-65400是Apple macOS中的一个身份验证不当问题，CVSS评分为9.8，可能允许攻击者绕过身份验证机制。虽然其他三个漏洞的具体技术细节未在摘要中披露，但它们被纳入KEV目录凸显了组织优先进行修补和缓解的紧迫性。

CISA的KEV目录是联邦机构和私营部门实体识别和修复被积极利用漏洞的关键资源。安全团队应立即评估其对这些漏洞的暴露情况，并应用供应商提供的补丁或缓解措施，以降低受损风险。

{{< netrunner-insight >}}

对于SOC分析师来说，这些CVE被添加到CISA的KEV目录是一个明确的信号，应优先考虑检测和响应工作。确保您的漏洞管理计划包括对这些特定产品的立即修补，并监控网络流量以寻找利用迹象。DevSecOps团队应将KEV数据集成到其CI/CD管道中，以阻止依赖易受攻击组件的部署。

{{< /netrunner-insight >}}

---

**[在 The Hacker News 上阅读全文 ›](https://thehackernews.com/2026/08/critical-macos-sharepoint-vcenter-and.html)**
