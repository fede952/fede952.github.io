---
title: "Klue OAuth侵害：IcarusハッカーがSalesforceトークンを窃取"
date: "2026-06-20T09:59:52Z"
original_date: "2026-06-19T22:31:04"
lang: "ja"
translationKey: "klue-oauth-breach-icarus-hackers-steal-salesforce-tokens"
author: "NewsBot (Validated by Federico Sella)"
description: "Klue、Salesforce統合に影響するOAuthトークン盗難を確認；Icarus恐喝グループが犯行声明、被害者リスト拡大中。"
original_url: "https://www.bleepingcomputer.com/news/security/klue-oauth-breach-victim-list-grows-as-icarus-hackers-claim-attack/"
source: "BleepingComputer"
severity: "High"
target: "Klue市場情報プラットフォーム"
cve: null
cvss: null
kev: null
tags: ["news", "cybersecurity"]
news-categories: ["cybersecurity"]
layout: "news"
draft: false
---

Klue、Salesforce統合に影響するOAuthトークン盗難を確認；Icarus恐喝グループが犯行声明、被害者リスト拡大中。

{{< cyber-report severity="High" source="BleepingComputer" target="Klue市場情報プラットフォーム" >}}

市場情報プラットフォームKlueは、脅威アクターが顧客のSalesforce環境に接続するために使用されるOAuthトークンを盗んだセキュリティインシデントを確認した。新たに出現した「Icarus」恐喝グループが犯行を主張し、被害を受けた顧客リストは拡大している。

{{< ad-banner >}}

盗まれたOAuthトークンにより、攻撃者は追加の認証なしにSalesforceデータにアクセスできる可能性があり、Klueの顧客に重大なリスクをもたらす。このインシデントは、OAuthトークンの露出の危険性と、堅牢なトークンライフサイクル管理の必要性を浮き彫りにしている。

Icarusグループが攻撃を公に主張する中、KlueのSalesforce統合を利用する組織は、関連するOAuthトークンを直ちに失効させてローテーションし、不正アクセスを監視すべきである。侵害の全容は依然調査中である。

{{< netrunner-insight >}}

このインシデントは、OAuthトークンを機密認証情報として保護することの極めて重要性を強調している。SOCアナリストは、異常なSalesforce API呼び出しの監視を優先し、トークンの有効期限ポリシーを徹底すべきである。DevSecOpsチームは、侵害時の影響範囲を限定するために、厳格なトークンスコーピングとローテーションメカニズムを実装しなければならない。

{{< /netrunner-insight >}}

---

**[完全な記事を BleepingComputer で読む ›](https://www.bleepingcomputer.com/news/security/klue-oauth-breach-victim-list-grows-as-icarus-hackers-claim-attack/)**
