---
title: "未修补的Windows搜索URI漏洞泄露NTLMv2哈希"
date: "2026-06-03T11:53:18Z"
original_date: "2026-06-03T10:18:52"
lang: "zh-cn"
translationKey: "unpatched-windows-search-uri-flaw-leaks-ntlmv2-hashes"
author: "NewsBot (Validated by Federico Sella)"
description: "研究人员披露了Windows search: URI处理程序中一个未修补的漏洞，该漏洞可能暴露NTLMv2哈希，类似于CVE-2026-33829截图工具缺陷。"
original_url: "https://thehackernews.com/2026/06/unpatched-windows-search-uri.html"
source: "The Hacker News"
severity: "High"
target: "Windows search: URI处理程序"
cve: null
cvss: null
kev: null
tags: ["news", "cybersecurity"]
news-categories: ["cybersecurity"]
layout: "news"
draft: false
---

研究人员披露了Windows search: URI处理程序中一个未修补的漏洞，该漏洞可能暴露NTLMv2哈希，类似于CVE-2026-33829截图工具缺陷。

{{< cyber-report severity="High" source="The Hacker News" target="Windows search: URI处理程序" >}}

Huntress的网络安全研究人员披露了Windows search: URI处理程序中一个未修补的漏洞细节，该漏洞可能允许攻击者窃取NTLMv2哈希。此问题让人联想到CVE-2026-33829，即Windows截图工具ms-screensketch: URI处理程序中的一个欺骗漏洞，同样会暴露NTLM哈希。

{{< ad-banner >}}

新发现的缺陷存在于search: URI方案中，该方案用于启动Windows搜索查询。通过制作恶意链接或文件触发search: URI处理程序，攻击者可以强制目标系统向远程服务器进行身份验证，从而泄露用户的NTLMv2哈希。该哈希随后可被离线破解或用于中继攻击。

截至发布日期，微软尚未发布官方补丁。建议组织关注更新，并在修复可用之前考虑通过组策略或端点安全工具阻止search: URI处理程序。

{{< netrunner-insight >}}

这是一个经典的NTLM中继向量，SOC分析师应在身份验证日志中密切关注。DevSecOps工程师应立即审查其环境中URI处理程序的使用情况，并考虑应用缓解措施，如禁用NTLMv2或强制SMB签名。在微软修补此问题之前，请假设search: URI是凭据窃取的潜在入口点。

{{< /netrunner-insight >}}

---

**[在 The Hacker News 上阅读全文 ›](https://thehackernews.com/2026/06/unpatched-windows-search-uri.html)**
