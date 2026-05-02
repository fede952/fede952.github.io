---
title: "ABB Ability Symphony Plus 工程软件缺陷可导致代码执行"
date: "2026-05-02T08:20:38Z"
original_date: "2026-04-30T12:00:00"
lang: "zh-cn"
translationKey: "abb-ability-symphony-plus-engineering-flaws-enable-code-execution"
author: "NewsBot (Validated by Federico Sella)"
description: "CISA 警告称，ABB Ability Symphony Plus 工程软件因使用过时的 PostgreSQL 存在漏洞，可在受影响系统上执行任意代码。"
original_url: "https://www.cisa.gov/news-events/ics-advisories/icsa-26-120-06"
source: "CISA"
severity: "High"
target: "ABB Ability Symphony Plus 工程软件"
cve: "CVE-2023-5869"
cvss: 8.8
kev: null
tags: ["news", "cybersecurity"]
news-categories: ["cybersecurity"]
layout: "news"
draft: false
---

CISA 警告称，ABB Ability Symphony Plus 工程软件因使用过时的 PostgreSQL 存在漏洞，可在受影响系统上执行任意代码。

{{< cyber-report severity="High" source="CISA" target="ABB Ability Symphony Plus 工程软件" cve="CVE-2023-5869" cvss="8.8" >}}

CISA 发布了一份公告（ICSA-26-120-06），详细说明了 ABB Ability Symphony Plus 工程软件中的多个漏洞，这些漏洞源于使用了 PostgreSQL 13.11 及更早版本。缺陷包括整数溢出、SQL 注入、TOCTOU 竞态条件和权限下降错误，可能允许经过身份验证的攻击者在系统上执行任意代码。

{{< ad-banner >}}

受影响版本涵盖 Ability Symphony Plus 2.2 至 2.4 SP2 RU1。鉴于该产品在全球化工、关键制造、能源以及水务等关键基础设施领域的部署，这些漏洞尤其令人担忧。

最值得关注的漏洞 CVE-2023-5869 的 CVSS 评分为 8.8，涉及整数溢出，可由经过身份验证的 PostgreSQL 用户通过精心构造的数据触发。成功利用可能导致系统完全受损，凸显了立即修补的必要性。

{{< netrunner-insight >}}

该公告强调了 OT 环境中过时依赖项的风险。SOC 分析师应优先对 ABB Symphony Plus 实例进行资产发现，并确保 PostgreSQL 更新至 13.11 以上版本。DevSecOps 团队必须将依赖项扫描集成到工业控制系统的 CI/CD 流水线中，以便及早捕获此类继承的漏洞。

{{< /netrunner-insight >}}

---

**[在 CISA 上阅读全文 ›](https://www.cisa.gov/news-events/ics-advisories/icsa-26-120-06)**
