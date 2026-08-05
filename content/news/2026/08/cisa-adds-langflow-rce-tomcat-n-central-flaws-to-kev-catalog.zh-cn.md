---
title: "CISA将Langflow RCE、Tomcat、N-central漏洞加入KEV目录"
date: "2026-08-05T09:30:51Z"
original_date: "2026-08-05T07:40:39"
lang: "zh-cn"
translationKey: "cisa-adds-langflow-rce-tomcat-n-central-flaws-to-kev-catalog"
slug: "cisa-adds-langflow-rce-tomcat-n-central-flaws-to-kev-catalog"
author: "NewsBot (Validated by Federico Sella)"
description: "CISA标记三个被积极利用的漏洞，包括CVSS 9.8的Langflow RCE（CVE-2026-9198），敦促立即修补。"
original_url: "https://thehackernews.com/2026/08/cisa-flags-langflow-rce-tomcat-and-n.html"
source: "The Hacker News"
severity: "Critical"
target: "Langflow、Apache Tomcat、N-central"
cve: "CVE-2026-9198"
cvss: 9.8
kev: true
tags: ["news", "cybersecurity"]
news-categories: ["cybersecurity"]
layout: "news"
draft: false
---

CISA标记三个被积极利用的漏洞，包括CVSS 9.8的Langflow RCE（CVE-2026-9198），敦促立即修补。

{{< cyber-report severity="Critical" source="The Hacker News" target="Langflow、Apache Tomcat、N-central" cve="CVE-2026-9198" cvss="9.8" kev="true" >}}

美国网络安全和基础设施安全局（CISA）已将三个漏洞添加到其已知被利用漏洞（KEV）目录中，引用积极利用的证据。其中包括CVE-2026-9198，这是Langflow中的一个严重代码注入漏洞，允许未经身份验证的攻击者实现完全远程代码执行。该漏洞的CVSS评分为9.8，表明风险严重。

{{< ad-banner >}}

另外两个漏洞影响Apache Tomcat和N-central，但摘要中未提供具体细节。CISA的KEV目录是已知被利用漏洞的优先列表，联邦机构必须在规定时间内修复这些漏洞。敦促各组织审查该目录并立即应用补丁。

这些漏洞的纳入强调了及时补丁管理和威胁情报的重要性。安全团队应监控与这些CVE相关的入侵指标，并确保其资产不暴露于已知攻击向量。

{{< netrunner-insight >}}

对于SOC分析师，优先监控针对Langflow、Tomcat和N-central的利用尝试，因为这些现在已被确认为活跃目标。DevSecOps应加快修补，特别是面向互联网的实例，并考虑为利用后活动实施额外的检测规则。鉴于关键的CVSS评分，将CVE-2026-9198视为最高风险，并验证是否发生未经授权的访问。

{{< /netrunner-insight >}}

---

**[在 The Hacker News 上阅读全文 ›](https://thehackernews.com/2026/08/cisa-flags-langflow-rce-tomcat-and-n.html)**
