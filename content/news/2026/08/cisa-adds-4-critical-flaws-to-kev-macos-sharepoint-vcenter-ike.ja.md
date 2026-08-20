---
title: "CISA、KEVに重大な脆弱性4件を追加：macOS、SharePoint、vCenter、IKE"
date: "2026-08-20T07:34:38Z"
original_date: "2026-08-19T11:01:48"
lang: "ja"
translationKey: "cisa-adds-4-critical-flaws-to-kev-macos-sharepoint-vcenter-ike"
slug: "cisa-adds-4-critical-flaws-to-kev-macos-sharepoint-vcenter-ike"
author: "NewsBot (Validated by Federico Sella)"
description: "CISAは、macOS、SharePoint、vCenter、Microsoft IKEにおける4つの重大な脆弱性が積極的に悪用されているとして、直ちにパッチを適用するよう警告しています。"
original_url: "https://thehackernews.com/2026/08/critical-macos-sharepoint-vcenter-and.html"
source: "The Hacker News"
severity: "Critical"
target: "Apple macOS"
cve: "CVE-2026-65400"
cvss: 9.8
kev: true
tags: ["news", "cybersecurity"]
news-categories: ["cybersecurity"]
layout: "news"
draft: false
---

CISAは、macOS、SharePoint、vCenter、Microsoft IKEにおける4つの重大な脆弱性が積極的に悪用されているとして、直ちにパッチを適用するよう警告しています。

{{< cyber-report severity="Critical" source="The Hacker News" target="Apple macOS" cve="CVE-2026-65400" cvss="9.8" kev="true" >}}

米国サイバーセキュリティ・インフラストラクチャセキュリティ庁（CISA）は、既知の悪用された脆弱性（KEV）カタログに4つの重大な脆弱性を追加しました。これは、実際に悪用が行われていることを示しています。これらの脆弱性は、Apple macOS、Microsoft SharePoint、VMware vCenter、およびMicrosoftのIKEプロトコルに影響を及ぼし、エンタープライズ環境に重大なリスクをもたらします。

{{< ad-banner >}}

リストされた脆弱性の中には、CVSSスコア9.8のApple macOSにおける不適切な認証の問題であるCVE-2026-65400が含まれており、攻撃者が認証メカニズムを回避できる可能性があります。他の3つの脆弱性の具体的な技術的詳細は要約では開示されていませんが、KEVカタログへの掲載は、組織がパッチ適用と緩和策を優先する緊急性を強調しています。

CISAのKEVカタログは、連邦政府機関や民間企業が積極的に悪用されている脆弱性を特定し、修復するための重要なリソースとして機能します。セキュリティチームは、これらの脆弱性への露出を直ちに評価し、ベンダー提供のパッチや回避策を適用して、侵害のリスクを軽減する必要があります。

{{< netrunner-insight >}}

SOCアナリストにとって、これらのCVEがCISAのKEVカタログに追加されたことは、検出と対応の取り組みを優先する明確なシグナルです。脆弱性管理プログラムにこれらの特定の製品に対する即時パッチ適用を含め、ネットワークトラフィックを悪用の兆候について監視してください。DevSecOpsチームは、KEVデータをCI/CDパイプラインに統合して、脆弱なコンポーネントに依存するデプロイをブロックする必要があります。

{{< /netrunner-insight >}}

---

**[完全な記事を The Hacker News で読む ›](https://thehackernews.com/2026/08/critical-macos-sharepoint-vcenter-and.html)**
