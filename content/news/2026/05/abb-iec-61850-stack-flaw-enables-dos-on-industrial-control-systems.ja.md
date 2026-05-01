---
title: "ABB IEC 61850 スタックの脆弱性により産業用制御システムでDoSが可能に"
date: "2026-05-01T09:03:14Z"
original_date: "2026-04-30T12:00:00"
lang: "ja"
translationKey: "abb-iec-61850-stack-flaw-enables-dos-on-industrial-control-systems"
author: "NewsBot (Validated by Federico Sella)"
description: "CISAは、ABBのIEC 61850 MMS実装における非公開報告の脆弱性がSystem 800xAおよびSymphony Plus製品に影響し、デバイス障害やサービス拒否を引き起こす可能性があると警告しています。"
original_url: "https://www.cisa.gov/news-events/ics-advisories/icsa-26-120-01"
source: "CISA"
severity: "High"
target: "ABB System 800xA, Symphony Plus IEC 61850"
cve: null
cvss: null
kev: null
tags: ["news", "cybersecurity"]
news-categories: ["cybersecurity"]
layout: "news"
draft: false
---

CISAは、ABBのIEC 61850 MMS実装における非公開報告の脆弱性がSystem 800xAおよびSymphony Plus製品に影響し、デバイス障害やサービス拒否を引き起こす可能性があると警告しています。

{{< cyber-report severity="High" source="CISA" target="ABB System 800xA, Symphony Plus IEC 61850" >}}

CISAは、ABBのIEC 61850通信スタックのMMSクライアントアプリケーション実装に関する脆弱性について勧告（ICSA-26-120-01）を発行しました。この欠陥は、System 800xAおよびSymphony Plusラインの複数の製品（AC800M CI868、Symphony Plus SD Series CI850、PM 877、S+ Operationsを含む）に影響します。悪用には、サイトのIEC 61850ネットワークへの事前アクセスが必要です。

{{< ad-banner >}}

悪用に成功すると、PM 877、CI850、CI868モジュールにデバイス障害が発生し、手動での再起動が必要になります。S+ Operationsノードの場合、攻撃によりIEC 61850通信ドライバーがクラッシュし、繰り返されるとサービス拒否状態を引き起こします。ただし、ノード全体の可用性と機能は影響を受けず、GOOSEプロトコル通信も影響を受けません。System 800xA IEC61850 Connectも脆弱ではありません。

影響を受けるファームウェアバージョンは複数のブランチにわたり、S+ Operations 6.2.0006.0まで、およびさまざまなPM 877リリースが含まれます。勧告ではCVE識別子やCVSSスコアは提供されていません。これらの製品を使用する組織は、勧告を確認し、ネットワークセグメンテーションやアクセス制御などの緩和策を適用して、IEC 61850ネットワークへの露出を制限する必要があります。

{{< netrunner-insight >}}

この脆弱性は、OT環境におけるネットワークセグメンテーションの重要性を浮き彫りにしています。悪用にはIEC 61850ネットワークへのアクセスが必要なため、そのネットワークを企業ITやインターネットから隔離することが重要です。SOCアナリストは異常なIEC 61850トラフィックを監視し、DevSecOpsエンジニアはパッチ適用を優先し、MMSプロトコルの異常に対する侵入検知の導入を検討すべきです。

{{< /netrunner-insight >}}

---

**[完全な記事を CISA で読む ›](https://www.cisa.gov/news-events/ics-advisories/icsa-26-120-01)**
