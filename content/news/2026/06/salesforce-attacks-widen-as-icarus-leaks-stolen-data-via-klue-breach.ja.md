---
title: "Salesforce攻撃が拡大、IcarusがKlue侵害を介して盗難データをリーク"
date: "2026-06-24T10:22:11Z"
original_date: "2026-06-23T20:44:09"
lang: "ja"
translationKey: "salesforce-attacks-widen-as-icarus-leaks-stolen-data-via-klue-breach"
author: "NewsBot (Validated by Federico Sella)"
description: "攻撃者はKlueのOAuthトークンを悪用してSalesforceインスタンスにアクセス。Icarusが盗難データをリークする中、新たな被害者が浮上。"
original_url: "https://www.darkreading.com/cyberattacks-data-breaches/scope-salesforce-attacks-expands-icarus-leaks-data"
source: "Dark Reading"
severity: "High"
target: "KlueのOAuthトークンを介したSalesforceインスタンス"
cve: null
cvss: null
kev: null
tags: ["news", "cybersecurity"]
news-categories: ["cybersecurity"]
layout: "news"
draft: false
---

攻撃者はKlueのOAuthトークンを悪用してSalesforceインスタンスにアクセス。Icarusが盗難データをリークする中、新たな被害者が浮上。

{{< cyber-report severity="High" source="Dark Reading" target="KlueのOAuthトークンを介したSalesforceインスタンス" >}}

Salesforceを標的とした進行中の攻撃の範囲が拡大し、Icarusとして追跡される脅威アクターが複数の被害者から盗んだデータをリークしています。攻撃者はまずアプリケーションベンダーKlueを侵害し、そのOAuthトークンを悪用して顧客のSalesforce環境に不正アクセスしました。

{{< ad-banner >}}

Dark Readingによると、最初の開示後に新たな被害者が現れ、この攻撃キャンペーンがこれまで考えられていたよりも広範囲であることが示されています。OAuthトークンの使用により、攻撃者は従来の認証制御を回避し、通常のアラートを発動させることなくSalesforceデータに直接アクセスできました。

KlueなどのサードパーティベンダーとSalesforce統合を利用している組織は、OAuthトークンの権限を監査し、異常なアクセスパターンを監視するよう求められています。Icarusグループは盗難データのリークを開始しており、影響を受ける企業の迅速な対応が急務となっています。

{{< netrunner-insight >}}

この攻撃は、SaaSエコシステムにおけるOAuthトークン悪用のリスクを浮き彫りにしています。SOCアナリストは、統合されたサードパーティアプリからの異常なAPIコールやトークン使用の監視を優先すべきです。DevSecOpsチームは、厳格なトークンライフサイクル管理を実施し、ジャストインタイムの権限を導入して影響範囲を制限する必要があります。

{{< /netrunner-insight >}}

---

**[完全な記事を Dark Reading で読む ›](https://www.darkreading.com/cyberattacks-data-breaches/scope-salesforce-attacks-expands-icarus-leaks-data)**
