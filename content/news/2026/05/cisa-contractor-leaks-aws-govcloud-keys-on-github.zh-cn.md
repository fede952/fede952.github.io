---
title: "CISA承包商在GitHub上泄露AWS GovCloud密钥"
date: "2026-05-19T10:35:27Z"
original_date: "2026-05-18T20:48:21"
lang: "zh-cn"
translationKey: "cisa-contractor-leaks-aws-govcloud-keys-on-github"
author: "NewsBot (Validated by Federico Sella)"
description: "一名CISA承包商在公共GitHub仓库中暴露了AWS GovCloud凭据和内部构建细节，这标志着最严重的政府数据泄露事件之一。"
original_url: "https://krebsonsecurity.com/2026/05/cisa-admin-leaked-aws-govcloud-keys-on-github/"
source: "Krebs on Security"
severity: "Critical"
target: "CISA AWS GovCloud账户"
cve: null
cvss: null
kev: null
tags: ["news", "cybersecurity"]
news-categories: ["cybersecurity"]
layout: "news"
draft: false
---

一名CISA承包商在公共GitHub仓库中暴露了AWS GovCloud凭据和内部构建细节，这标志着最严重的政府数据泄露事件之一。

{{< cyber-report severity="Critical" source="Krebs on Security" target="CISA AWS GovCloud账户" >}}

直到上周末，网络安全与基础设施安全局（CISA）的一名承包商维护着一个公共GitHub仓库，该仓库暴露了多个高权限AWS GovCloud账户的凭据以及大量CISA内部系统的信息。安全专家表示，该公共存档包含详细说明CISA如何内部构建、测试和部署软件的文件，并称这是近年来最严重的政府数据泄露事件之一。

{{< ad-banner >}}

暴露的凭据可能允许攻击者访问敏感的政府云环境和内部系统，可能导致数据外泄或进一步入侵。此事件凸显了即使在政府承包商中，硬编码密钥在公共仓库中的风险。

{{< netrunner-insight >}}

此次泄露凸显了自动秘密扫描和严格仓库访问控制的迫切需求。SOC分析师应优先监控公共代码仓库中暴露的凭据，而DevSecOps团队必须强制执行秘密管理策略，并立即轮换任何可能已被泄露的密钥。

{{< /netrunner-insight >}}

---

**[在 Krebs on Security 上阅读全文 ›](https://krebsonsecurity.com/2026/05/cisa-admin-leaked-aws-govcloud-keys-on-github/)**
