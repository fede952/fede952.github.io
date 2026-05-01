---
title: "CISA 警告 ABB PCM600 路径遍历漏洞可导致远程代码执行"
date: "2026-05-01T08:59:15Z"
original_date: "2026-04-30T12:00:00"
lang: "zh-cn"
translationKey: "cisa-warns-of-abb-pcm600-path-traversal-flaw-leading-to-rce"
author: "NewsBot (Validated by Federico Sella)"
description: "ABB PCM600 版本 1.5 至 2.13 存在路径遍历漏洞（CVE-2018-1002208），可能允许任意代码执行。请更新至版本 2.14。"
original_url: "https://www.cisa.gov/news-events/ics-advisories/icsa-26-120-02"
source: "CISA"
severity: "Medium"
target: "ABB PCM600"
cve: "CVE-2018-1002208"
cvss: null
kev: null
tags: ["news", "cybersecurity"]
news-categories: ["cybersecurity"]
layout: "news"
draft: false
---

ABB PCM600 版本 1.5 至 2.13 存在路径遍历漏洞（CVE-2018-1002208），可能允许任意代码执行。请更新至版本 2.14。

{{< cyber-report severity="Medium" source="CISA" target="ABB PCM600" cve="CVE-2018-1002208" >}}

CISA 发布了一份安全公告（ICSA-26-120-02），详细说明了 ABB PCM600（一种保护和控制 IED 管理器）中的漏洞。该漏洞编号为 CVE-2018-1002208，存在于 SharpZip.dll 库中，涉及对受限目录路径名的不当限制（路径遍历）。成功利用该漏洞可能允许攻击者向系统节点发送特制消息，从而导致任意代码执行。

{{< ad-banner >}}

受影响的产品版本为 PCM600 1.5 至 2.13（含）。ABB 已发布版本 2.14 以修复该问题。但请注意，RE_630 保护继电器与 PCM600 2.14 不兼容，因此使用早期版本并配备 RE_630 的用户必须依赖系统级防御措施，如 ABB 通用安全建议所述。

该公告强调，该产品在全球关键制造业领域部署。尽管公告中未提供 CVSS 评分，但该漏洞可能执行代码，因此应尽快修补。组织应优先更新至 PCM600 2.14，并对无法立即更新的系统实施网络分段和访问控制。

{{< netrunner-insight >}}

ABB PCM600 中的这个路径遍历漏洞提醒我们，像 SharpZip.dll 这样的遗留依赖项可能会引入风险。对于 SOC 分析师，请监控发往 PCM600 节点的异常网络流量，特别是可能表明利用尝试的特制消息。DevSecOps 工程师应盘点所有 PCM600 实例并计划升级到版本 2.14，同时通过补偿控制措施解决与 RE_630 继电器的兼容性问题。

{{< /netrunner-insight >}}

---

**[在 CISA 上阅读全文 ›](https://www.cisa.gov/news-events/ics-advisories/icsa-26-120-02)**
