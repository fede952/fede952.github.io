---
title: "Polymarket因第三方供应商遭供应链攻击损失300万美元"
date: "2026-06-28T09:58:42Z"
original_date: "2026-06-26T18:04:12"
lang: "zh-cn"
translationKey: "polymarket-loses-3m-in-supply-chain-attack-via-third-party-vendor"
author: "NewsBot (Validated by Federico Sella)"
description: "黑客在入侵第三方供应商后向Polymarket前端注入恶意脚本，导致客户损失300万美元。该平台将全额赔偿受害者。"
original_url: "https://www.bleepingcomputer.com/news/security/polymarket-customers-lose-3-million-in-supply-chain-attack/"
source: "BleepingComputer"
severity: "High"
target: "Polymarket前端用户"
cve: null
cvss: null
kev: null
tags: ["news", "cybersecurity"]
news-categories: ["cybersecurity"]
layout: "news"
draft: false
---

黑客在入侵第三方供应商后向Polymarket前端注入恶意脚本，导致客户损失300万美元。该平台将全额赔偿受害者。

{{< cyber-report severity="High" source="BleepingComputer" target="Polymarket前端用户" >}}

Polymarket，一个去中心化预测市场平台，披露攻击者入侵了第三方供应商，向前端注入了恶意脚本，导致客户损失约300万美元。该事件被描述为供应链攻击，目标是平台用户界面以窃取资金。

{{< ad-banner >}}

该公司表示将全额赔偿受影响的客户，但具体受害者人数尚未披露。此次入侵凸显了DeFi和加密平台中第三方依赖的风险，在这些平台中，前端完整性对交易安全至关重要。

虽然未提供具体的CVE或CVSS评分，但攻击向量——通过入侵供应商来篡改前端代码——强调了需要强有力的供应链安全措施，包括代码签名、完整性检查和供应商风险评估。

{{< netrunner-insight >}}

此事件是典型的前端完整性供应链攻击。SOC分析师应监控Web应用程序中未经授权的脚本注入，特别是那些依赖第三方库或CDN的应用。DevSecOps团队必须强制执行严格的内容安全策略（CSP）、子资源完整性（SRI）检查以及定期供应商审计，以减轻此类风险。

{{< /netrunner-insight >}}

---

**[在 BleepingComputer 上阅读全文 ›](https://www.bleepingcomputer.com/news/security/polymarket-customers-lose-3-million-in-supply-chain-attack/)**
