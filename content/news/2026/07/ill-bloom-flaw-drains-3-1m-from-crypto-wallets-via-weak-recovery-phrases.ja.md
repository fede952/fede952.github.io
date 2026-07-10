---
title: "Ill Bloomの脆弱性により、弱いリカバリーフレーズを介して暗号通貨ウォレットから310万ドルが流出"
date: "2026-07-10T10:19:16Z"
original_date: "2026-07-10T09:00:05"
lang: "ja"
translationKey: "ill-bloom-flaw-drains-3-1m-from-crypto-wallets-via-weak-recovery-phrases"
slug: "ill-bloom-flaw-drains-3-1m-from-crypto-wallets-via-weak-recovery-phrases"
author: "NewsBot (Validated by Federico Sella)"
description: "攻撃者は、Ill Bloomと呼ばれる暗号通貨ウォレットのリカバリーフレーズ生成における脆弱性を悪用し、組織的な一斉操作で310万ドルを盗み出した。"
original_url: "https://thehackernews.com/2026/07/attackers-exploit-ill-bloom.html"
source: "The Hacker News"
severity: "High"
target: "暗号通貨ウォレット"
cve: null
cvss: null
kev: null
tags: ["news", "cybersecurity"]
news-categories: ["cybersecurity"]
layout: "news"
draft: false
---

攻撃者は、Ill Bloomと呼ばれる暗号通貨ウォレットのリカバリーフレーズ生成における脆弱性を悪用し、組織的な一斉操作で310万ドルを盗み出した。

{{< cyber-report severity="High" source="The Hacker News" target="暗号通貨ウォレット" >}}

セキュリティ企業Coinspectは、暗号通貨ウォレットソフトウェアにおけるIll Bloomと名付けられた脆弱性を公開した。この脆弱性は、リカバリーフレーズ生成における乱数の弱さを悪用し、攻撃者が資金を引き出すことを可能にする。この欠陥は、一部のウォレットがウォレットの資金へのアクセスを制御するニーモニックフレーズを作成する方法に影響を与える。乱数性が不十分な場合、攻撃者はフレーズを計算し、ウォレットを完全に制御できる。

{{< ad-banner >}}

Coinspectは、攻撃者が5月にこの脆弱性を組織的な一斉操作ですでに悪用し、複数のウォレットから約310万ドルを盗んだことを確認した。攻撃の正確な日付と全容は明らかにされていないが、このインシデントは暗号アプリケーションにおける安全な乱数生成の重要性を浮き彫りにしている。

ウォレットユーザーは、使用しているソフトウェアが暗号学的に安全な乱数生成器を使用していることを確認し、監査済みの乱数実装を備えたウォレットに資金を移行することを検討するよう推奨される。開発者はエントロピーソースをレビューし、BIP39などの業界標準に準拠していることを確認すべきである。

{{< netrunner-insight >}}

このインシデントは、暗号鍵生成における弱いエントロピーへの依存の危険性を強調している。SOCアナリストは異常なウォレット取引や大量の資金移動を監視し、DevSecOpsエンジニアはセキュリティクリティカルなアプリケーションにおけるすべての乱数生成を監査すべきである。予測可能な乱数性は必ず悪用されると想定せよ。

{{< /netrunner-insight >}}

---

**[完全な記事を The Hacker News で読む ›](https://thehackernews.com/2026/07/attackers-exploit-ill-bloom.html)**
