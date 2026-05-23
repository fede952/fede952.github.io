---
title: "CISA承包商在公开GitHub上泄露AWS GovCloud密钥"
date: "2026-05-23T09:02:01Z"
original_date: "2026-05-22T16:34:24"
lang: "zh-cn"
translationKey: "cisa-contractor-leaks-aws-govcloud-keys-on-public-github"
author: "NewsBot (Validated by Federico Sella)"
description: "立法者要求解释，此前一名CISA承包商故意在公开GitHub账户上发布了AWS GovCloud密钥和机构机密，而CISA正竭力控制此次泄露。"
original_url: "https://krebsonsecurity.com/2026/05/lawmakers-demand-answers-as-cisa-tries-to-contain-data-leak/"
source: "Krebs on Security"
severity: "High"
target: "CISA AWS GovCloud环境"
cve: null
cvss: null
kev: null
tags: ["news", "cybersecurity"]
news-categories: ["cybersecurity"]
layout: "news"
draft: false
---

立法者要求解释，此前一名CISA承包商故意在公开GitHub账户上发布了AWS GovCloud密钥和机构机密，而CISA正竭力控制此次泄露。

{{< cyber-report severity="High" source="Krebs on Security" target="CISA AWS GovCloud环境" >}}

美国国会两院议员正要求网络安全与基础设施安全局（CISA）作出解释，此前KrebsOnSecurity报道称，一名CISA承包商故意在公开GitHub账户上发布了AWS GovCloud密钥和大量其他机构机密。此次泄露暴露了敏感凭证和数据，引发了立法者对CISA安全实践的紧急质询。

{{< ad-banner >}}

CISA目前正竭力控制泄露并撤销泄露的凭证。该事件凸显了承包商访问敏感系统所带来的风险，以及保护云环境（尤其是政府机构使用的云环境）所面临的挑战。该机构尚未披露泄露数据的全部范围或涉事承包商的身份。

{{< netrunner-insight >}}

此事件凸显了在云环境中对承包商活动实施严格访问控制和持续监控的迫切需求。SOC分析师应优先审计GitHub仓库中泄露的凭证，并部署自动化秘密扫描工具。DevSecOps团队必须强制执行最小权限访问，并确保一旦怀疑有任何泄露，立即轮换所有云密钥。

{{< /netrunner-insight >}}

---

**[在 Krebs on Security 上阅读全文 ›](https://krebsonsecurity.com/2026/05/lawmakers-demand-answers-as-cisa-tries-to-contain-data-leak/)**
