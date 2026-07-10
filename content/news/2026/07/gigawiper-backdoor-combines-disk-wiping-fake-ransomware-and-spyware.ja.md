---
title: "GigaWiperバックドアはディスク消去、偽ランサムウェア、スパイウェアを組み合わせる"
date: "2026-07-10T10:21:21Z"
original_date: "2026-07-09T18:08:07"
lang: "ja"
translationKey: "gigawiper-backdoor-combines-disk-wiping-fake-ransomware-and-spyware"
slug: "gigawiper-backdoor-combines-disk-wiping-fake-ransomware-and-spyware"
author: "NewsBot (Validated by Federico Sella)"
description: "MicrosoftがGigaWiperを発見。これはモジュール式のWindowsバックドアで、ディスクワイパー、偽ランサムウェア、スパイウェアの3つの破壊的ツールをバンドルし、エンドポイントに深刻な脅威をもたらす。"
original_url: "https://thehackernews.com/2026/07/new-gigawiper-windows-backdoor-bundles.html"
source: "The Hacker News"
severity: "High"
target: "Windowsエンドポイント"
cve: null
cvss: null
kev: null
tags: ["news", "cybersecurity"]
news-categories: ["cybersecurity"]
layout: "news"
draft: false
---

MicrosoftがGigaWiperを発見。これはモジュール式のWindowsバックドアで、ディスクワイパー、偽ランサムウェア、スパイウェアの3つの破壊的ツールをバンドルし、エンドポイントに深刻な脅威をもたらす。

{{< cyber-report severity="High" source="The Hacker News" target="Windowsエンドポイント" >}}

Microsoftは、GigaWiperと名付けられた新しい破壊的なWindowsバックドアを特定しました。これは、3つの古い悪意のあるプログラムを単一のモジュール式フレームワークに統合したものです。このバックドアは、オペレーターに選択可能なコマンドメニューを提供し、各コマンドは異なる種類の損害を与えるように設計されています。完全なディスク消去、Windowsシステムドライブの上書き、またはキーが決して保存されないファイルを暗号化する偽ランサムウェアの実行などです。

{{< ad-banner >}}

GigaWiperのモジュール設計により、攻撃者は標的環境に基づいて破壊行動を調整できます。ディスク消去機能と偽ランサムウェアの組み合わせは、主な目的が金銭的利益ではなく、最大限の混乱とデータ損失を引き起こすことであることを示唆しています。これらの手法の組み合わせにより、GigaWiperは破壊的なサイバー作戦において多用途で危険なツールとなっています。

具体的な配布経路は明らかにされていませんが、ディスク全体を消去しランサムウェア攻撃をシミュレートするバックドアの能力は、高度な洗練性を示しています。組織はエンドポイント検出および対応（EDR）ソリューションを優先し、堅牢なバックアップ戦略を確保して、このような脅威の影響を軽減すべきです。

{{< netrunner-insight >}}

SOCアナリストにとって、GigaWiperは、大量ファイル操作やディスクレベル書き込みをフラグする行動検出ルールの必要性を強調しています。DevSecOpsチームは、バックアップの整合性を検証し、復旧手順を定期的にテストすべきです。偽ランサムウェアは従来の復号アプローチを回避できるため、検証されていないランサムウェアインシデントは、反証されるまで潜在的なワイパー攻撃として扱ってください。

{{< /netrunner-insight >}}

---

**[完全な記事を The Hacker News で読む ›](https://thehackernews.com/2026/07/new-gigawiper-windows-backdoor-bundles.html)**
