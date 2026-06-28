---
title: "Polymarket、サプライチェーン攻撃で300万ドルを損失—サードパーティベンダー経由"
date: "2026-06-28T09:58:42Z"
original_date: "2026-06-26T18:04:12"
lang: "ja"
translationKey: "polymarket-loses-3m-in-supply-chain-attack-via-third-party-vendor"
author: "NewsBot (Validated by Federico Sella)"
description: "ハッカーがサードパーティベンダーを侵害し、Polymarketのフロントエンドに悪意のあるスクリプトを注入、顧客に300万ドルの損失をもたらした。プラットフォームは被害者に全額返金する方針。"
original_url: "https://www.bleepingcomputer.com/news/security/polymarket-customers-lose-3-million-in-supply-chain-attack/"
source: "BleepingComputer"
severity: "High"
target: "Polymarketのフロントエンドユーザー"
cve: null
cvss: null
kev: null
tags: ["news", "cybersecurity"]
news-categories: ["cybersecurity"]
layout: "news"
draft: false
---

ハッカーがサードパーティベンダーを侵害し、Polymarketのフロントエンドに悪意のあるスクリプトを注入、顧客に300万ドルの損失をもたらした。プラットフォームは被害者に全額返金する方針。

{{< cyber-report severity="High" source="BleepingComputer" target="Polymarketのフロントエンドユーザー" >}}

分散型予測市場プラットフォームPolymarketは、攻撃者がサードパーティベンダーを侵害し、フロントエンドに悪意のあるスクリプトを注入した結果、顧客に約300万ドルの損失が生じたと発表した。サプライチェーン攻撃とされるこのインシデントは、プラットフォームのユーザーインターフェースを標的に資金を吸い上げた。

{{< ad-banner >}}

同社は影響を受けた顧客に全額返金すると表明したが、被害者の正確な数は非公開としている。この侵害は、フロントエンドの整合性が取引のセキュリティに不可欠なDeFiや暗号資産プラットフォームにおける、サードパーティ依存のリスクを浮き彫りにしている。

特定のCVEやCVSSスコアは提供されていないが、ベンダーを侵害してフロントエンドコードを改ざんするという攻撃ベクトルは、コード署名、整合性チェック、ベンダーリスク評価を含む堅牢なサプライチェーンセキュリティ対策の必要性を強調している。

{{< netrunner-insight >}}

このインシデントは、フロントエンドの整合性を標的にした典型的なサプライチェーン攻撃である。SOCアナリストは、特にサードパーティのライブラリやCDNに依存するWebアプリケーションにおける不正なスクリプト注入を監視すべきである。DevSecOpsチームは、厳格なコンテンツセキュリティポリシー（CSP）、サブリソース整合性（SRI）チェック、定期的なベンダー監査を実施して、こうしたリスクを軽減する必要がある。

{{< /netrunner-insight >}}

---

**[完全な記事を BleepingComputer で読む ›](https://www.bleepingcomputer.com/news/security/polymarket-customers-lose-3-million-in-supply-chain-attack/)**
