---
title: "Ubiquiti、UniFi OSの最大深刻度コマンドインジェクション脆弱性を修正"
date: "2026-07-08T09:24:49Z"
original_date: "2026-07-08T08:15:20"
lang: "ja"
translationKey: "ubiquiti-patches-max-severity-command-injection-flaw-in-unifi-os"
slug: "ubiquiti-patches-max-severity-command-injection-flaw-in-unifi-os"
author: "NewsBot (Validated by Federico Sella)"
description: "UbiquitiはUniFi OSの7件のクリティカルな脆弱性に対するセキュリティアップデートをリリースしました。その中には最大深刻度のコマンドインジェクションの欠陥が含まれています。管理者は直ちにパッチを適用するよう求められています。"
original_url: "https://www.bleepingcomputer.com/news/security/ubiquiti-warns-of-new-max-severity-unifi-os-vulnerability/"
source: "BleepingComputer"
severity: "Critical"
target: "UniFi OS"
cve: null
cvss: null
kev: null
tags: ["news", "cybersecurity"]
news-categories: ["cybersecurity"]
layout: "news"
draft: false
---

UbiquitiはUniFi OSの7件のクリティカルな脆弱性に対するセキュリティアップデートをリリースしました。その中には最大深刻度のコマンドインジェクションの欠陥が含まれています。管理者は直ちにパッチを適用するよう求められています。

{{< cyber-report severity="Critical" source="BleepingComputer" target="UniFi OS" >}}

Ubiquitiは、ネットワーキングデバイスを動かすオペレーティングシステムであるUniFi OSにおいて、7件のクリティカルな脆弱性に対処するセキュリティアップデートをリリースしました。その中で最も深刻なものは、コマンドインジェクション攻撃で悪用される可能性のある最大深刻度の欠陥であり、攻撃者が影響を受けるシステム上で任意のコマンドを実行できる可能性があります。

{{< ad-banner >}}

これらの脆弱性は、UniFi OSを実行する幅広いUbiquiti製品に影響を与えます。最初のアドバイザリでは特定のCVE識別子は開示されませんでしたが、同社はすべてのユーザーに対し、悪用のリスクを軽減するために最新のファームウェアアップデートを直ちに適用するよう求めています。

これらの脆弱性、特にコマンドインジェクションの欠陥のクリティカルな性質を考慮すると、Ubiquiti機器を使用している組織はパッチ適用を優先すべきです。現時点では活発な悪用の証拠は報告されていませんが、その深刻度はセキュリティチームによる即時の対応を必要とします。

{{< netrunner-insight >}}

これは、Ubiquiti UniFi機器を運用している組織にとって必須のパッチ適用状況です。ネットワークインフラにおけるコマンドインジェクションの欠陥はレッドチームの夢であり、概念実証エクスプロイトがすぐに表面化することが予想されます。パッチ適用を優先し、影響を受けるデバイスからの異常なアウトバウンド接続を監視してください。

{{< /netrunner-insight >}}

---

**[完全な記事を BleepingComputer で読む ›](https://www.bleepingcomputer.com/news/security/ubiquiti-warns-of-new-max-severity-unifi-os-vulnerability/)**
