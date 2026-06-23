---
title: "MITRE ATT&CK v19 全面革新防御规避战术"
date: "2026-06-23T10:34:05Z"
original_date: "2026-06-23T10:14:50"
lang: "zh-cn"
translationKey: "mitre-att-ck-v19-overhauls-defense-evasion-with-new-tactics"
author: "NewsBot (Validated by Federico Sella)"
description: "MITRE ATT&CK v19 引入结构性变化，弃用防御规避（TA0005），新增隐蔽与削弱防御战术。同时提供迁移指南。"
original_url: "https://www.cybersecurity360.it/nuove-minacce/mitre-attck-v19-ecco-le-novita-strutturali-della-nuova-versione/"
source: "Cybersecurity360"
severity: "Info"
target: "MITRE ATT&CK 框架用户"
cve: null
cvss: null
kev: null
tags: ["news", "cybersecurity"]
news-categories: ["cybersecurity"]
layout: "news"
draft: false
---

MITRE ATT&CK v19 引入结构性变化，弃用防御规避（TA0005），新增隐蔽与削弱防御战术。同时提供迁移指南。

{{< cyber-report severity="Info" source="Cybersecurity360" target="MITRE ATT&CK 框架用户" >}}

MITRE 发布了 ATT&CK 框架第 19 版，引入了重大的结构性修改。最显著的变化是弃用了防御规避战术（TA0005），取而代之的是两个新战术：隐蔽与削弱防御。此次重组旨在更精细地对攻击者逃避检测和破坏防御的行为进行分类。

{{< ad-banner >}}

本次更新包含一份迁移指南，帮助组织将威胁模型和检测规则从旧战术过渡到新战术。建议从业者审查当前对防御规避的映射，并将技术重新分配到适当的新战术，以保持覆盖。

虽然此次发布未涉及特定的 CVE 或漏洞，但框架更新对 SOC 运营和威胁狩猎有影响。团队应更新其 MITRE ATT&CK 参考，并调整依赖已弃用战术 ID 的分析规则。

{{< netrunner-insight >}}

对于 SOC 分析师而言，这意味着需要更新引用 TA0005 的检测规则和威胁狩猎查询。DevSecOps 工程师应审查 CI/CD 管道安全映射，确保与新战术对齐。迁移指南对于避免过渡期间出现覆盖缺口至关重要。

{{< /netrunner-insight >}}

---

**[在 Cybersecurity360 上阅读全文 ›](https://www.cybersecurity360.it/nuove-minacce/mitre-attck-v19-ecco-le-novita-strutturali-della-nuova-versione/)**
