---
title: "LastPass、Klueサプライチェーン攻撃によるデータ侵害を確認"
date: "2026-06-24T10:23:36Z"
original_date: "2026-06-23T13:58:25"
lang: "ja"
translationKey: "lastpass-confirms-data-breach-via-klue-supply-chain-attack"
author: "NewsBot (Validated by Federico Sella)"
description: "LastPassは、攻撃者がサードパーティアプリKlueからOAuthトークンを盗み、Salesforce環境内の顧客データにアクセスしたことを明らかにした。"
original_url: "https://www.bleepingcomputer.com/news/security/lastpass-confirms-data-breach-in-klue-supply-chain-attack/"
source: "BleepingComputer"
severity: "High"
target: "LastPass Salesforce環境"
cve: null
cvss: null
kev: null
tags: ["news", "cybersecurity"]
news-categories: ["cybersecurity"]
layout: "news"
draft: false
---

LastPassは、攻撃者がサードパーティアプリKlueからOAuthトークンを盗み、Salesforce環境内の顧客データにアクセスしたことを明らかにした。

{{< cyber-report severity="High" source="BleepingComputer" target="LastPass Salesforce環境" >}}

LastPassは、今月初めのKlueサプライチェーン攻撃で同社のOAuthトークンが盗まれ、ハッカーがSalesforce環境から顧客データにアクセスしたことを確認した。6月23日に開示されたこの侵害は、サードパーティ統合とトークン盗難のリスクを浮き彫りにしている。

{{< ad-banner >}}

攻撃者は、サードパーティアプリケーションKlueから侵害されたOAuthトークンを使用して、LastPassのSalesforceインスタンスに不正アクセスした。このサプライチェーン攻撃により、脅威アクターは通常の認証アラートをトリガーすることなく顧客データを流出させることができた。

LastPassは影響を受ける顧客に通知し、侵害されたトークンを無効化した。同社はまた、同様のインシデントを防ぐためにサードパーティのアクセスポリシーを見直している。この侵害は、OAuthトークンの使用状況を監視し、統合サービスに厳格なアクセス制御を実装することの重要性を強調している。

{{< netrunner-insight >}}

このインシデントは、OAuthトークンの悪用によるサプライチェーンリスクの典型例である。SOCアナリストは、異常なトークン使用の監視を優先し、トークン有効期限ポリシーを実装すべきである。DevSecOpsチームは、サードパーティ統合に対して最小権限アクセスを強制し、ブラスト半径を減らすために短命トークンの使用を検討する必要がある。

{{< /netrunner-insight >}}

---

**[完全な記事を BleepingComputer で読む ›](https://www.bleepingcomputer.com/news/security/lastpass-confirms-data-breach-in-klue-supply-chain-attack/)**
