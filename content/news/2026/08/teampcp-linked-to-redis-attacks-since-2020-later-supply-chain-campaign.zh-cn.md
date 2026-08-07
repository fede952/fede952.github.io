---
title: "TeamPCP自2020年起与Redis攻击有关，后来涉及供应链活动"
date: "2026-08-07T08:10:37Z"
original_date: "2026-08-07T06:50:05"
lang: "zh-cn"
translationKey: "teampcp-linked-to-redis-attacks-since-2020-later-supply-chain-campaign"
slug: "teampcp-linked-to-redis-attacks-since-2020-later-supply-chain-campaign"
author: "NewsBot (Validated by Federico Sella)"
description: "新分析将TeamPCP与可追溯至2020年的Redis攻击联系起来，揭示了在供应链重点之前多年的基础设施入侵。"
original_url: "https://thehackernews.com/2026/08/teampcp-linked-to-redis-attacks-dating.html"
source: "The Hacker News"
severity: "Medium"
target: "面向互联网的基础设施"
cve: null
cvss: null
kev: null
tags: ["news", "cybersecurity"]
news-categories: ["cybersecurity"]
layout: "news"
draft: false
---

新分析将TeamPCP与可追溯至2020年的Redis攻击联系起来，揭示了在供应链重点之前多年的基础设施入侵。

{{< cyber-report severity="Medium" source="The Hacker News" target="面向互联网的基础设施" >}}

最近的一项分析发现，被称为TeamPCP的威胁行为者至少自2020年以来一直活跃在网络犯罪领域，表明其长期入侵面向互联网的基础设施。该组织的活动现已与后来的软件供应链活动相关联，表明其运营策略发生了演变。

{{< ad-banner >}}

早期Redis攻击与供应链活动之间的联系得到了重叠域名、恶意软件部署路径、暂存技术和后端基础设施的支持。这些共同点为同一行为者应对这两类活动负责提供了有力证据，凸显了历史威胁情报在归因和理解现代攻击中的重要性。

对于防御者而言，这一时间线强调了监控可能跨越多年的入侵指标的必要性，并考虑威胁行为者从机会性攻击转向更有针对性的供应链操作的可能性。调查结果还强调了跨组织共享威胁情报以识别此类长期模式的价值。

{{< netrunner-insight >}}

对于SOC分析师来说，这份报告强调了将历史指标与当前威胁关联起来的重要性——TeamPCP使用重叠基础设施意味着旧的入侵指标可能仍然相关。DevSecOps团队应将Redis等面向互联网的服务视为高价值目标，并确保强大的补丁管理和监控，因为攻击者可能在发动攻击前潜伏多年。供应链防御者还应审查第三方组件是否与已知的恶意基础设施有关联，因为这个群体展示了从直接攻击到更隐蔽的供应链入侵的明显演变。

{{< /netrunner-insight >}}

---

**[在 The Hacker News 上阅读全文 ›](https://thehackernews.com/2026/08/teampcp-linked-to-redis-attacks-dating.html)**
