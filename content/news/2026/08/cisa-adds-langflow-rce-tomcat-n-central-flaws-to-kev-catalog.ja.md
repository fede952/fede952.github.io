---
title: "CISA、Langflow RCE、Tomcat、N-centralの脆弱性をKEVカタログに追加"
date: "2026-08-05T09:30:51Z"
original_date: "2026-08-05T07:40:39"
lang: "ja"
translationKey: "cisa-adds-langflow-rce-tomcat-n-central-flaws-to-kev-catalog"
slug: "cisa-adds-langflow-rce-tomcat-n-central-flaws-to-kev-catalog"
author: "NewsBot (Validated by Federico Sella)"
description: "CISAは、CVSS 9.8のLangflow RCE（CVE-2026-9198）を含む、積極的に悪用されている3つの脆弱性をフラグし、即時のパッチ適用を促しています。"
original_url: "https://thehackernews.com/2026/08/cisa-flags-langflow-rce-tomcat-and-n.html"
source: "The Hacker News"
severity: "Critical"
target: "Langflow、Apache Tomcat、N-central"
cve: "CVE-2026-9198"
cvss: 9.8
kev: true
tags: ["news", "cybersecurity"]
news-categories: ["cybersecurity"]
layout: "news"
draft: false
---

CISAは、CVSS 9.8のLangflow RCE（CVE-2026-9198）を含む、積極的に悪用されている3つの脆弱性をフラグし、即時のパッチ適用を促しています。

{{< cyber-report severity="Critical" source="The Hacker News" target="Langflow、Apache Tomcat、N-central" cve="CVE-2026-9198" cvss="9.8" kev="true" >}}

米国サイバーセキュリティ・インフラストラクチャセキュリティ庁（CISA）は、積極的な悪用の証拠を挙げて、3つの脆弱性を既知の悪用された脆弱性（KEV）カタログに追加しました。その中には、CVE-2026-9198、Langflowの重大なコードインジェクションの欠陥があり、認証されていない攻撃者が完全なリモートコード実行を達成できるようにします。この脆弱性はCVSSスコア9.8で、深刻なリスクを示しています。

{{< ad-banner >}}

他の2つの欠陥はApache TomcatとN-centralに影響しますが、要約では具体的な詳細は提供されていません。CISAのKEVカタログは、悪用されることが知られている脆弱性の優先順位付きリストであり、連邦機関は指定された期間内にこれらを修復する必要があります。組織はカタログを確認し、直ちにパッチを適用するよう求められています。

これらの脆弱性の追加は、タイムリーなパッチ管理と脅威インテリジェンスの重要性を強調しています。セキュリティチームは、これらのCVEに関連する侵害の指標を監視し、資産が既知の攻撃ベクトルにさらされていないことを確認する必要があります。

{{< netrunner-insight >}}

SOCアナリストにとって、Langflow、Tomcat、N-centralに対する悪用の試みの監視を優先してください。これらは現在確認されたアクティブなターゲットです。DevSecOpsは、特にインターネットに面したインスタンスのパッチ適用を迅速化し、侵害後の活動に対する追加の検出ルールの実装を検討する必要があります。重大なCVSSスコアを考慮して、CVE-2026-9198を最上位のリスクとして扱い、不正アクセスが発生していないことを検証してください。

{{< /netrunner-insight >}}

---

**[完全な記事を The Hacker News で読む ›](https://thehackernews.com/2026/08/cisa-flags-langflow-rce-tomcat-and-n.html)**
