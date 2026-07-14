---
title: "CISA GitHub泄露事件：AWS GovCloud密钥暴露长达六个月"
date: "2026-07-14T09:01:14Z"
original_date: "2026-07-13T15:03:28"
lang: "zh-cn"
translationKey: "cisa-github-leak-exposes-aws-govcloud-keys-for-six-months"
slug: "cisa-github-leak-exposes-aws-govcloud-keys-for-six-months"
author: "NewsBot (Validated by Federico Sella)"
description: "一名承包商在GitHub上泄露了CISA内部凭证，包括AWS GovCloud密钥，暴露时间长达六个月。专家为安全团队总结了关键教训。"
original_url: "https://krebsonsecurity.com/2026/07/lessons-learned-from-cisas-recent-github-leak/"
source: "Krebs on Security"
severity: "High"
target: "CISA GitHub仓库"
cve: null
cvss: null
kev: null
tags: ["news", "cybersecurity"]
news-categories: ["cybersecurity"]
layout: "news"
draft: false
---

一名承包商在GitHub上泄露了CISA内部凭证，包括AWS GovCloud密钥，暴露时间长达六个月。专家为安全团队总结了关键教训。

{{< cyber-report severity="High" source="Krebs on Security" target="CISA GitHub仓库" >}}

网络安全和基础设施安全局（CISA）披露了一起数据泄露事件，一名承包商无意中将包括AWS GovCloud密钥在内的数十个内部凭证发布在公开的GitHub仓库中。这些凭证暴露了近六个月，直到KrebsOnSecurity通知该机构。

{{< ad-banner >}}

CISA的事后分析指出了其初始响应中的不足，例如检测延迟以及缺乏对公共仓库中秘密的自动扫描。这一事件凸显了实施强大的秘密管理和持续监控代码仓库的必要性。

专家建议实施预提交钩子、定期秘密扫描和严格的访问控制，以防止类似泄露。使用临时凭证和自动轮换也可以减轻暴露密钥的影响。

{{< netrunner-insight >}}

这一事件是为何必须将秘密扫描集成到CI/CD流水线中（而不仅仅是提交后）的典型案例。SOC分析师应优先处理公共仓库暴露的告警，DevSecOps团队应对承包商实施最小权限访问。自动化凭证轮换，并考虑使用GitLeaks或TruffleHog等工具及早发现泄露。

{{< /netrunner-insight >}}

---

**[在 Krebs on Security 上阅读全文 ›](https://krebsonsecurity.com/2026/07/lessons-learned-from-cisas-recent-github-leak/)**
