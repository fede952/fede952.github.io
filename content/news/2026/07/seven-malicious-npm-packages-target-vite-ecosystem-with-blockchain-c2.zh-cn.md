---
title: "七个恶意npm包利用区块链C2瞄准Vite生态系统"
date: "2026-07-19T09:03:59Z"
original_date: "2026-07-17T18:54:51"
lang: "zh-cn"
translationKey: "seven-malicious-npm-packages-target-vite-ecosystem-with-blockchain-c2"
slug: "seven-malicious-npm-packages-target-vite-ecosystem-with-blockchain-c2"
author: "NewsBot (Validated by Federico Sella)"
description: "Checkmarx揭露ViteVenom活动，使用基于区块链的C2基础设施，通过七个恶意npm包针对Vite前端工具链分发远程访问木马。"
original_url: "https://thehackernews.com/2026/07/seven-malicious-vite-npm-packages-use.html"
source: "The Hacker News"
severity: "High"
target: "Vite前端工具链生态系统"
cve: null
cvss: null
kev: null
tags: ["news", "cybersecurity"]
news-categories: ["cybersecurity"]
layout: "news"
draft: false
---

Checkmarx揭露ViteVenom活动，使用基于区块链的C2基础设施，通过七个恶意npm包针对Vite前端工具链分发远程访问木马。

{{< cyber-report severity="High" source="The Hacker News" target="Vite前端工具链生态系统" >}}

来自Checkmarx的网络安全研究人员发现了一组七个恶意npm包，它们针对Vite前端工具链生态系统，作为软件供应链攻击的一部分。该活动代号为ViteVenom，是此前观察到的ChainVeil行动的扩展，后者使用了前所未有的四层基于区块链的命令与控制（C2）基础设施，横跨Tron网络。

{{< ad-banner >}}

这些恶意包旨在向受感染系统传递远程访问木马（RAT），使攻击者能够窃取数据并保持持久访问。使用区块链进行C2通信使得检测和清除更加困难，因为该基础设施是去中心化的，并且能够抵抗传统的沉没技术。

在开发流程中使用Vite的组织应立即审计其依赖项，以识别已发现的恶意包，并实施严格的包完整性检查。此事件突显了软件供应链攻击日益复杂化，攻击者利用合法的开发工具和去中心化网络来逃避检测。

{{< netrunner-insight >}}

对于SOC分析师来说，监控到区块链节点的出站连接和异常的DNS查询有助于检测这种C2技术。DevSecOps团队应强制实施包签名，并使用依赖扫描工具在已知恶意包进入构建管道之前将其阻止。

{{< /netrunner-insight >}}

---

**[在 The Hacker News 上阅读全文 ›](https://thehackernews.com/2026/07/seven-malicious-vite-npm-packages-use.html)**
