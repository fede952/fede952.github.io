---
title: "KlueのOAuth侵害により、IcarusがSalesforceデータを窃取"
date: "2026-06-20T10:03:21Z"
original_date: "2026-06-18T14:19:50"
lang: "ja"
translationKey: "klue-oauth-breach-enables-icarus-salesforce-data-theft"
author: "NewsBot (Validated by Federico Sella)"
description: "脅威アクターがKlueのOAuth侵害を悪用し、複数の組織からSalesforce CRMデータを盗み出す継続的な恐喝キャンペーンが行われている。"
original_url: "https://www.bleepingcomputer.com/news/security/klue-oauth-breach-linked-to-icarus-salesforce-data-theft-attacks/"
source: "BleepingComputer"
severity: "High"
target: "OAuth経由のSalesforce CRMデータ"
cve: null
cvss: null
kev: null
tags: ["news", "cybersecurity"]
news-categories: ["cybersecurity"]
layout: "news"
draft: false
---

脅威アクターがKlueのOAuth侵害を悪用し、複数の組織からSalesforce CRMデータを盗み出す継続的な恐喝キャンペーンが行われている。

{{< cyber-report severity="High" source="BleepingComputer" target="OAuth経由のSalesforce CRMデータ" >}}

市場情報プラットフォームのKlueがOAuth侵害を受け、脅威アクターグループ「Icarus」が複数の組織からSalesforce CRMデータを窃取した。攻撃者は侵害されたOAuthトークンを悪用して機密性の高い顧客関係管理データにアクセスし、それを流出させ、現在恐喝キャンペーンに利用している。

{{< ad-banner >}}

この侵害は、OAuth統合や重要なビジネスプラットフォームへのサードパーティアクセスに伴うリスクを浮き彫りにしている。Klueのサービスを利用する組織は、OAuthトークンポリシーを見直し、Salesforceインスタンスへの不正アクセスを監視するよう推奨される。

Icarusは、Salesforce環境を標的とした一連のデータ窃取攻撃に関連している。このグループの手口は、脆弱なOAuth設定やトークン管理の慣行を悪用し、CRMデータへの永続的なアクセスを獲得することである。

{{< netrunner-insight >}}

このインシデントは、厳格なOAuthトークンのライフサイクル管理とサードパーティ統合の継続的な監視の重要性を強調している。SOCアナリストは、OAuth許可の監査と、統合アプリからの異常なデータアクセスパターンを検出するための異常検知の実装を優先すべきである。

{{< /netrunner-insight >}}

---

**[完全な記事を BleepingComputer で読む ›](https://www.bleepingcomputer.com/news/security/klue-oauth-breach-linked-to-icarus-salesforce-data-theft-attacks/)**
