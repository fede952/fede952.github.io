---
title: "CISA、ActiveMQ Artemisの認証欠如を介したSiemens Opcenter RDnLの脆弱性を警告"
date: "2026-05-17T08:59:55Z"
original_date: "2026-05-14T12:00:00"
lang: "ja"
translationKey: "cisa-warns-of-siemens-opcenter-rdnl-flaw-via-activemq-artemis-missing-auth"
author: "NewsBot (Validated by Federico Sella)"
description: "Siemens Opcenter RDnLはCVE-2026-27446の影響を受けます。これはActiveMQ Artemisにおける認証欠如の脆弱性であり、認証されていない隣接攻撃者がメッセージを注入または流出させることを可能にします。"
original_url: "https://www.cisa.gov/news-events/ics-advisories/icsa-26-134-09"
source: "CISA"
severity: "High"
target: "Siemens Opcenter RDnL"
cve: "CVE-2026-27446"
cvss: 7.1
kev: null
tags: ["news", "cybersecurity"]
news-categories: ["cybersecurity"]
layout: "news"
draft: false
---

Siemens Opcenter RDnLはCVE-2026-27446の影響を受けます。これはActiveMQ Artemisにおける認証欠如の脆弱性であり、認証されていない隣接攻撃者がメッセージを注入または流出させることを可能にします。

{{< cyber-report severity="High" source="CISA" target="Siemens Opcenter RDnL" cve="CVE-2026-27446" cvss="7.1" >}}

CISAは、Apache ActiveMQ Artemisの重要な機能に対する認証欠如の脆弱性を詳述した勧告（ICSA-26-134-09）を公開しました。この脆弱性はSiemens Opcenter RDnLに影響を与えます。CVE-2026-27446として追跡され、CVSS v3スコア7.1のこの欠陥により、隣接ネットワーク内の認証されていない攻撃者が、対象のブローカーに不正なブローカーへのアウトバウンドCoreフェデレーション接続を強制できます。これにより、不正なブローカーを介した任意のキューへのメッセージ注入や任意のキューからのメッセージ流出が可能になります。

{{< ad-banner >}}

この脆弱性は、Siemens Opcenter RDnLのすべてのバージョンに影響します。自動更新機能の欠如とメッセージに機密情報が含まれていないため、整合性への影響は低いと見なされますが、可用性への影響とメッセージ操作の可能性は依然として重要です。ActiveMQ Artemisは修正をリリースしており、Siemensは直ちに最新バージョンに更新することを推奨しています。

世界中の重要な製造部門での展開を考慮すると、Opcenter RDnLを使用する組織はパッチ適用を優先すべきです。隣接ネットワーク攻撃ベクトルは直接的な露出を減らしますが、セグメント化された環境でもリスクをもたらします。ブルーチームは、異常なCoreフェデレーション接続や不正なブローカー活動を監視する必要があります。

{{< netrunner-insight >}}

SOCアナリストは、ActiveMQ Artemisブローカーからの予期しないアウトバウンドCoreフェデレーション接続を監視してください。これが悪用の主要な指標です。DevSecOpsチームは直ちに最新のActiveMQ Artemisバージョンに更新し、Coreプロトコルアクセスを信頼できるネットワークのみに制限する必要があります。この欠陥は、直接的な影響が低いように見えても、ミドルウェアコンポーネントにおける認証欠如のリスクを浮き彫りにしています。

{{< /netrunner-insight >}}

---

**[完全な記事を CISA で読む ›](https://www.cisa.gov/news-events/ics-advisories/icsa-26-134-09)**
