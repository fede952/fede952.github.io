---
title: "Ill Bloom漏洞利用弱恢复短语从加密钱包中盗取310万美元"
date: "2026-07-10T10:19:16Z"
original_date: "2026-07-10T09:00:05"
lang: "zh-cn"
translationKey: "ill-bloom-flaw-drains-3-1m-from-crypto-wallets-via-weak-recovery-phrases"
slug: "ill-bloom-flaw-drains-3-1m-from-crypto-wallets-via-weak-recovery-phrases"
author: "NewsBot (Validated by Federico Sella)"
description: "攻击者利用加密货币钱包恢复短语生成中的一个名为Ill Bloom的漏洞，在一次协同行动中盗取了310万美元。"
original_url: "https://thehackernews.com/2026/07/attackers-exploit-ill-bloom.html"
source: "The Hacker News"
severity: "High"
target: "加密货币钱包"
cve: null
cvss: null
kev: null
tags: ["news", "cybersecurity"]
news-categories: ["cybersecurity"]
layout: "news"
draft: false
---

攻击者利用加密货币钱包恢复短语生成中的一个名为Ill Bloom的漏洞，在一次协同行动中盗取了310万美元。

{{< cyber-report severity="High" source="The Hacker News" target="加密货币钱包" >}}

安全公司Coinspect披露了加密货币钱包软件中的一个名为Ill Bloom的漏洞，该漏洞允许攻击者通过利用恢复短语生成中的弱随机性来盗取资金。该漏洞影响某些钱包创建用于控制钱包资金访问的助记词的方式。当随机性不足时，攻击者可以计算出该短语并获得对钱包的完全控制。

{{< ad-banner >}}

Coinspect确认，攻击者已于5月利用该漏洞进行了一次协同攻击，从多个钱包中盗取了约310万美元。攻击的具体日期和全部范围尚未披露，但该事件凸显了在加密应用中安全随机数生成的关键重要性。

建议钱包用户验证其软件是否使用加密安全的随机数生成器，并考虑将资金迁移到具有经过审计的随机性实现的钱包。开发者应审查其熵源，并确保符合BIP39等行业标准。

{{< netrunner-insight >}}

此事件凸显了在加密密钥生成中依赖弱熵的危险性。SOC分析师应监控异常的钱包交易或大规模资金转移，而DevSecOps工程师必须审计安全关键型应用中的所有随机数生成。始终假设可预测的随机性将被利用。

{{< /netrunner-insight >}}

---

**[在 The Hacker News 上阅读全文 ›](https://thehackernews.com/2026/07/attackers-exploit-ill-bloom.html)**
