---
title: "SAP npm包遭凭证窃取供应链攻击"
date: "2026-05-03T08:51:39Z"
original_date: "2026-04-29T16:26:00"
lang: "zh-cn"
translationKey: "sap-npm-packages-hit-by-credential-stealing-supply-chain-attack"
author: "NewsBot (Validated by Federico Sella)"
description: "一场名为“Mini Shai-Hulud”的攻击活动针对SAP相关的npm包，植入凭证窃取恶意软件，影响多个包。多家公司的研究人员警告供应链风险。"
original_url: "https://thehackernews.com/2026/04/sap-npm-packages-compromised-by-mini.html"
source: "The Hacker News"
severity: "High"
target: "SAP相关的npm包"
cve: null
cvss: null
kev: null
tags: ["news", "cybersecurity"]
news-categories: ["cybersecurity"]
layout: "news"
draft: false
---

一场名为“Mini Shai-Hulud”的攻击活动针对SAP相关的npm包，植入凭证窃取恶意软件，影响多个包。多家公司的研究人员警告供应链风险。

{{< cyber-report severity="High" source="The Hacker News" target="SAP相关的npm包" >}}

网络安全研究人员发现了一起针对SAP相关npm包的供应链攻击活动。据Aikido Security、Onapsis、OX Security、SafeDep、Socket、StepSecurity和Wiz的报告，该活动名为“Mini Shai-Hulud”，通过被攻陷的包部署凭证窃取恶意软件。

{{< ad-banner >}}

此次攻击影响了多个与SAP关联的npm包，但具体包名和版本尚未披露。恶意软件旨在窃取凭证，可能使攻击者能够访问敏感的SAP环境及下游系统。

这一事件凸显了软件供应链日益增长的威胁，尤其是对于像SAP这样的企业关键平台。使用受影响包的组织应审计其依赖关系，并轮换任何可能已被泄露的凭证。

{{< netrunner-insight >}}

对于SOC分析师和DevSecOps团队，此次攻击强调了在npm包上进行严格的依赖扫描和完整性检查的必要性。监控来自SAP相关系统的异常出站连接，并考虑实施运行时应用自我保护（RASP）以检测凭证窃取。立即轮换所有可能通过被攻陷包暴露的凭证。

{{< /netrunner-insight >}}

---

**[在 The Hacker News 上阅读全文 ›](https://thehackernews.com/2026/04/sap-npm-packages-compromised-by-mini.html)**
