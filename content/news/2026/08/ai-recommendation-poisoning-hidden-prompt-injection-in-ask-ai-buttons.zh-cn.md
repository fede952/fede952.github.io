---
title: "AI推荐投毒：Ask AI按钮中的隐藏提示注入"
date: "2026-08-07T08:08:58Z"
original_date: "2026-08-06T11:30:00"
lang: "zh-cn"
translationKey: "ai-recommendation-poisoning-hidden-prompt-injection-in-ask-ai-buttons"
slug: "ai-recommendation-poisoning-hidden-prompt-injection-in-ask-ai-buttons"
author: "NewsBot (Validated by Federico Sella)"
description: "一种新的提示注入类别滥用AI助手中的预填深度链接，无需恶意软件或漏洞利用即可悄悄改变LLM记忆。"
original_url: "https://thehackernews.com/2026/08/ai-recommendation-poisoning-how-ask-ai.html"
source: "The Hacker News"
severity: "Medium"
target: "带有AI助手的商业网站"
cve: null
cvss: null
kev: null
tags: ["news", "cybersecurity"]
news-categories: ["cybersecurity"]
layout: "news"
draft: false
---

一种新的提示注入类别滥用AI助手中的预填深度链接，无需恶意软件或漏洞利用即可悄悄改变LLM记忆。

{{< cyber-report severity="Medium" source="The Hacker News" target="带有AI助手的商业网站" >}}

一种新的提示注入类别正在商业网站上蔓延，无需恶意软件、窃取的凭据或零日漏洞。它滥用了几乎所有主流AI助手中内置的标准功能：预填深度链接。已观察到生产网站在营销和竞争对手对比页面的“Ask AI”按钮中嵌入隐藏的提示注入载荷。

{{< ad-banner >}}

当用户点击此类按钮时，预填深度链接会触发AI助手处理嵌入的载荷，从而可能悄悄改变LLM的记忆或行为。这种被称为“AI推荐投毒”的技术，对依赖AI生成推荐进行购买或决策的用户构成重大风险。

这种攻击向量特别隐蔽，因为它利用了用户与合法网站的可信交互。与需要直接用户输入的传统提示注入不同，此方法通过UI操作，使用户更难察觉。部署AI助手的组织应审计其深度链接处理，并实施防护措施以应对隐藏载荷。

{{< netrunner-insight >}}

对于SOC分析师而言，这凸显了将AI助手交互作为攻击面一部分进行监控的必要性。DevSecOps工程师应验证并清理任何来自外部内容的预填深度链接或提示。将AI助手视为不受信任的输入渠道，并对提示来源实施严格的允许列表。

{{< /netrunner-insight >}}

---

**[在 The Hacker News 上阅读全文 ›](https://thehackernews.com/2026/08/ai-recommendation-poisoning-how-ask-ai.html)**
