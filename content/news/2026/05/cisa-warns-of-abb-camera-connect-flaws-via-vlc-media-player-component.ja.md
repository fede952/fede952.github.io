---
title: "CISA、ABB Camera Connectの脆弱性を警告—VLCメディアプレーヤーコンポーネント経由"
date: "2026-05-27T10:51:57Z"
original_date: "2026-05-26T12:00:00"
lang: "ja"
translationKey: "cisa-warns-of-abb-camera-connect-flaws-via-vlc-media-player-component"
author: "NewsBot (Validated by Federico Sella)"
description: "ABB Ability Camera Connect バージョン1.5.0.14以下には、脆弱なVLCメディアプレーヤー2.2.4が含まれており、CVE-2024-46461を含む複数のメモリ破損バグが存在し、重大なリスクをもたらします。"
original_url: "https://www.cisa.gov/news-events/ics-advisories/icsa-26-146-05"
source: "CISA"
severity: "Critical"
target: "ABB Ability Camera Connect"
cve: "CVE-2024-46461"
cvss: 9.8
kev: null
tags: ["news", "cybersecurity"]
news-categories: ["cybersecurity"]
layout: "news"
draft: false
---

ABB Ability Camera Connect バージョン1.5.0.14以下には、脆弱なVLCメディアプレーヤー2.2.4が含まれており、CVE-2024-46461を含む複数のメモリ破損バグが存在し、重大なリスクをもたらします。

{{< cyber-report severity="Critical" source="CISA" target="ABB Ability Camera Connect" cve="CVE-2024-46461" cvss="9.8" >}}

CISAは勧告（ICSA-26-146-05）を発表し、ABB Ability Camera Connect バージョン1.5.0.14以下に複数の脆弱性があることを詳細に報告しました。これらの欠陥は、インストールパッケージにバンドルされている古いサードパーティコンポーネント、VLCメディアプレーヤーバージョン2.2.4に起因しています。バージョン1.5.0.15へのアップデートにより、脆弱なコンポーネントを置き換えることで問題が解決されます。

{{< ad-banner >}}

脆弱性には、ヒープベースのバッファオーバーフロー、整数アンダーフロー、範囲外書き込み、制御されない検索パス要素、整数オーバーフロー、オフバイワンエラー、範囲外読み取り、ダブルフリー、メモリバッファ内の操作の不適切な制限、および解放後使用が含まれます。特にCVE-2024-46461は、悪意を持って細工されたMMSストリームを介したVLCメディアプレーヤー3.0.20以前のヒープベースのオーバーフローを説明しており、サービス拒否を引き起こします。

CVSS v3スコア9.8で、これらの脆弱性はCriticalと評価されています。影響を受ける重要インフラセクターには、化学、商業施設、通信、重要製造、エネルギー、交通システムが含まれます。この製品は世界中で展開されており、悪用されると攻撃者がさまざまな方法でシステムを侵害する可能性があります。

{{< netrunner-insight >}}

この勧告は、サードパーティコンポーネントから継承された脆弱性のリスクを強調しています。SOCアナリストは、ABB Ability Camera Connectをバージョン1.5.0.15に優先的にパッチ適用し、VLCメディアプレーヤーの欠陥を標的とした悪用試行を監視する必要があります。DevSecOpsチームは、厳格なコンポーネントバージョン管理とバンドルライブラリの定期的なスキャンを実施しなければなりません。

{{< /netrunner-insight >}}

---

**[完全な記事を CISA で読む ›](https://www.cisa.gov/news-events/ics-advisories/icsa-26-146-05)**
