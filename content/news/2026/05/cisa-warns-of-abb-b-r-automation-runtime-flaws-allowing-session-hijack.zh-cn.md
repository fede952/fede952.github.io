---
title: "CISA警告：ABB B&R Automation Runtime漏洞可导致会话劫持"
date: "2026-05-22T10:20:32Z"
original_date: "2026-05-21T12:00:00"
lang: "zh-cn"
translationKey: "cisa-warns-of-abb-b-r-automation-runtime-flaws-allowing-session-hijack"
author: "NewsBot (Validated by Federico Sella)"
description: "ABB B&R Automation Runtime 6.4之前版本存在多个漏洞，攻击者可利用这些漏洞劫持会话或执行代码。CISA公告ICSA-26-141-04详细说明了修复措施。"
original_url: "https://www.cisa.gov/news-events/ics-advisories/icsa-26-141-04"
source: "CISA"
severity: "Medium"
target: "ABB B&R Automation Runtime"
cve: "CVE-2025-3449"
cvss: 6.1
kev: null
tags: ["news", "cybersecurity"]
news-categories: ["cybersecurity"]
layout: "news"
draft: false
---

ABB B&R Automation Runtime 6.4之前版本存在多个漏洞，攻击者可利用这些漏洞劫持会话或执行代码。CISA公告ICSA-26-141-04详细说明了修复措施。

{{< cyber-report severity="Medium" source="CISA" target="ABB B&R Automation Runtime" cve="CVE-2025-3449" cvss="6.1" >}}

CISA发布了公告ICSA-26-141-04，详细说明了ABB B&R Automation Runtime（一款用于工业自动化的软件平台）中的多个漏洞。这些漏洞由B&R内部安全分析发现，影响6.4之前的版本，包括CVE-2025-3449（可预测的会话标识符）、CVE-2025-3448（跨站脚本）和CVE-2025-11498（CSV文件中公式元素未正确中和）。未经身份验证的攻击者可利用这些漏洞劫持远程会话或在用户浏览器上下文中执行代码。

{{< ad-banner >}}

最严重的漏洞CVE-2025-3449存在于系统诊断管理器（SDM）组件中，CVSS v3评分为6.1。该漏洞允许未经身份验证的基于网络的攻击者利用可预测的数字或标识符接管已建立的会话。在Automation Runtime 6中，SDM默认禁用，从而降低了暴露风险，但组织应确认其保持关闭状态，除非明确需要。

ABB已发布Automation Runtime 6.4版本来修复这些问题。鉴于该产品在全球能源领域的部署，CISA敦促运营商尽快应用更新。公告指出，成功利用这些漏洞可能导致远程代码执行或会话接管，对工业控制环境构成重大风险。

{{< netrunner-insight >}}

对于SOC分析师：优先修补Automation Runtime实例，特别是启用了SDM的实例。可预测会话ID漏洞（CVE-2025-3449）可通过网络轻易利用。DevSecOps团队应确保SDM在生产环境中保持禁用，并验证没有暴露的实例可从不受信任的网络访问。监控异常会话活动作为检测信号。

{{< /netrunner-insight >}}

---

**[在 CISA 上阅读全文 ›](https://www.cisa.gov/news-events/ics-advisories/icsa-26-141-04)**
