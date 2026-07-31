---
title: "Azure Cosmos DBの脆弱性により、すべてのデータベースが露出する可能性があった"
date: "2026-07-31T09:37:51Z"
original_date: "2026-07-30T13:34:09"
lang: "ja"
translationKey: "azure-cosmos-db-flaw-could-have-exposed-all-databases"
slug: "azure-cosmos-db-flaw-could-have-exposed-all-databases"
author: "NewsBot (Validated by Federico Sella)"
description: "修正済みのAzure Cosmos DBの脆弱性により、サンドボックスエスケープとクロステナントのデータベースアクセスが可能になり、WizによってCosmosEscapeとして発見されました。"
original_url: "https://thehackernews.com/2026/07/azure-cosmos-db-flaw-exposed-platform.html"
source: "The Hacker News"
severity: "High"
target: "Azure Cosmos DB"
cve: null
cvss: null
kev: null
tags: ["news", "cybersecurity"]
news-categories: ["cybersecurity"]
layout: "news"
draft: false
---

修正済みのAzure Cosmos DBの脆弱性により、サンドボックスエスケープとクロステナントのデータベースアクセスが可能になり、WizによってCosmosEscapeとして発見されました。

{{< cyber-report severity="High" source="The Hacker News" target="Azure Cosmos DB" >}}

現在は修正済みのAzure Cosmos DBの脆弱性により、攻撃者がサービスのGremlinクエリサンドボックスをエスケープし、顧客テナントをまたいだデータベースへの完全な読み取りおよび書き込みアクセスを取得できる可能性がありました。この脆弱性はセキュリティ企業Wizによって発見され、エクスプロイトチェーンは「CosmosEscape」とコードネームが付けられました。

{{< ad-banner >}}

攻撃チェーンは、攻撃者が制御するGremlinデータベースに対する巧妙に細工されたクエリから始まりました。そこから攻撃者は基盤となるインフラストラクチャ上でコード実行を達成し、テナント間の分離を侵害する可能性がありました。

マイクロソフトはこの問題を修正しましたが、このインシデントはクラウドデータベースサービスにおけるテナント分離の重要性を浮き彫りにしています。Azure Cosmos DBを使用している組織は、セキュリティ設定を確認し、異常なアクティビティを監視する必要があります。

{{< netrunner-insight >}}

SOCアナリストにとって、これは異常なGremlinクエリや通常とは異なるデータベースアクセスパターンを監視する必要性を強調しています。DevSecOpsチームは、クラウドデータベースサービスが最小権限の原則で構成され、サンドボックスメカニズムが定期的に監査されることを確認する必要があります。これは修正されていますが、同様の欠陥が他のマネージドサービスにも存在する可能性があるため、プロアクティブな脅威ハンティングが不可欠です。

{{< /netrunner-insight >}}

---

**[完全な記事を The Hacker News で読む ›](https://thehackernews.com/2026/07/azure-cosmos-db-flaw-exposed-platform.html)**
