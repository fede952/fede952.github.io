---
title: "Siemens Solid EdgeのPARファイル解析の欠陥によりコード実行が可能に"
date: "2026-05-16T08:48:36Z"
original_date: "2026-05-14T12:00:00"
lang: "ja"
translationKey: "siemens-solid-edge-par-parsing-flaws-enable-code-execution"
author: "NewsBot (Validated by Federico Sella)"
description: "Siemens Solid Edge SE2026における2つのファイル解析の脆弱性により、特別に細工されたPARファイルを介して攻撃者が任意のコードを実行できる可能性があります。V226.0 Update 5に更新してください。"
original_url: "https://www.cisa.gov/news-events/ics-advisories/icsa-26-134-03"
source: "CISA"
severity: "High"
target: "Siemens Solid Edge SE2026"
cve: "CVE-2026-44411"
cvss: 7.8
kev: null
tags: ["news", "cybersecurity"]
news-categories: ["cybersecurity"]
layout: "news"
draft: false
---

Siemens Solid Edge SE2026における2つのファイル解析の脆弱性により、特別に細工されたPARファイルを介して攻撃者が任意のコードを実行できる可能性があります。V226.0 Update 5に更新してください。

{{< cyber-report severity="High" source="CISA" target="Siemens Solid Edge SE2026" cve="CVE-2026-44411" cvss="7.8" >}}

Update 5より前のSiemens Solid Edge SE2026は、アプリケーションが特別に細工されたPARファイルを読み取るときにトリガーされる2つのファイル解析の脆弱性の影響を受けます。これらの欠陥には、初期化されていないポインタへのアクセス（CVE-2026-44411）とスタックベースのバッファオーバーフロー（CVE-2026-44412）が含まれ、攻撃者がアプリケーションをクラッシュさせたり、現在のプロセスのコンテキストで任意のコードを実行したりする可能性があります。

{{< ad-banner >}}

これらの脆弱性のCVSS v3.1基本スコアは7.8（High）で、ベクトルはAV:L/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:Hであり、ローカルアクセス、低複雑性、特権不要、ユーザー操作が必要、機密性・完全性・可用性への高い影響を示しています。Siemensはこれらの問題に対処するためにバージョンV226.0 Update 5をリリースしており、ユーザーに直ちに更新するよう推奨しています。

世界中の重要な製造部門での展開を考慮すると、Solid Edgeを使用する組織はパッチ適用を優先すべきです。これらの脆弱性はユーザー操作（悪意のあるPARファイルを開くこと）を必要とするため、ユーザー意識向上トレーニングも補完的対策として推奨されます。

{{< netrunner-insight >}}

SOCアナリストは、Solid Edgeプロセスにおける異常なPARファイル処理やクラッシュを監視してください。DevSecOpsエンジニアは、アプリケーションホワイトリストを適用し、ファイルタイプを制限して攻撃対象領域を減らすべきです。これらはローカルでユーザー操作に依存する脆弱性であるため、フィッシングシミュレーションと不審なファイルオープンに対するエンドポイント検出ルールが重要な緩和策となります。

{{< /netrunner-insight >}}

---

**[完全な記事を CISA で読む ›](https://www.cisa.gov/news-events/ics-advisories/icsa-26-134-03)**
