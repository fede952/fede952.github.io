---
title: "Adobe、ColdFusionおよびCampaign ClassicのCVSS 10.0の脆弱性3件を修正"
date: "2026-08-13T08:18:27Z"
original_date: "2026-08-12T11:13:03"
lang: "ja"
translationKey: "adobe-patches-three-cvss-10-0-flaws-in-coldfusion-and-campaign-classic"
slug: "adobe-patches-three-cvss-10-0-flaws-in-coldfusion-and-campaign-classic"
author: "NewsBot (Validated by Federico Sella)"
description: "AdobeはColdFusion、Commerce、Campaign Classic向けの緊急アップデートをリリースし、CVSS 10.0の重大度を持つコマンドインジェクションおよび権限昇格の脆弱性に対処しました。"
original_url: "https://thehackernews.com/2026/08/adobe-patches-three-cvss-100-coldfusion.html"
source: "The Hacker News"
severity: "Critical"
target: "Adobe ColdFusion、Commerce、Campaign Classic"
cve: "CVE-2026-48362"
cvss: 10.0
kev: null
tags: ["news", "cybersecurity"]
news-categories: ["cybersecurity"]
layout: "news"
draft: false
---

AdobeはColdFusion、Commerce、Campaign Classic向けの緊急アップデートをリリースし、CVSS 10.0の重大度を持つコマンドインジェクションおよび権限昇格の脆弱性に対処しました。

{{< cyber-report severity="Critical" source="The Hacker News" target="Adobe ColdFusion、Commerce、Campaign Classic" cve="CVE-2026-48362" cvss="10.0" >}}

Adobeは、ColdFusion、Commerce、Campaign Classicにおける複数の重大な脆弱性に対処するため、緊急セキュリティアップデートをリリースしました。最も深刻なものはCVE-2026-48362で、ColdFusionにおけるCVSS 10.0評価のOSコマンドインジェクションの脆弱性であり、攻撃者が基盤となるシステム上で任意のコードを実行できる可能性があります。

{{< ad-banner >}}

コマンドインジェクションの欠陥に加えて、これらのアップデートは権限昇格につながる可能性のある他の重大な問題にも対処しています。これらの脆弱性が悪用されると、攻撃者は影響を受けるサーバーを完全に制御できる可能性があり、データ漏洩、横移動、またはインフラストラクチャのさらなる侵害につながる可能性があります。

CVSSスコアが最大であり、これらの製品がエンタープライズ環境で重要であることを考えると、即時のパッチ適用が強く推奨されます。組織はまた、これらの脆弱性に関連する侵害の指標についてセキュリティ監視を確認する必要があります。

{{< netrunner-insight >}}

CVSS 10.0の評価を持つこれらは、最も深刻なものです。積極的なエクスプロイトシナリオとして扱ってください。ColdFusionおよびCampaign Classicサーバーへのパッチ適用を直ちに優先し、侵害後の活動の兆候を確認してください。また、可能であればこれらのサービスをインターネットから隔離し、異常なコマンド実行パターンについてログを確認することを検討してください。

{{< /netrunner-insight >}}

---

**[完全な記事を The Hacker News で読む ›](https://thehackernews.com/2026/08/adobe-patches-three-cvss-100-coldfusion.html)**
