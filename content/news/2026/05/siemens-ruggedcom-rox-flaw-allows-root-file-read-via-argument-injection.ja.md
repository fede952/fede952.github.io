---
title: "Siemens Ruggedcom ROXの脆弱性により、引数インジェクションを介したルートファイルの読み取りが可能に"
date: "2026-05-17T09:01:07Z"
original_date: "2026-05-14T12:00:00"
lang: "ja"
translationKey: "siemens-ruggedcom-rox-flaw-allows-root-file-read-via-argument-injection"
author: "NewsBot (Validated by Federico Sella)"
description: "CISAは、複数のRuggedcom ROXデバイスに影響するCVE-2025-40948について警告しています。認証されたリモート攻撃者がルート権限で任意のファイルを読み取る可能性があります。バージョン2.17.1以降に更新してください。"
original_url: "https://www.cisa.gov/news-events/ics-advisories/icsa-26-134-02"
source: "CISA"
severity: "Medium"
target: "Siemens Ruggedcom ROXデバイス"
cve: "CVE-2025-40948"
cvss: 6.8
kev: null
tags: ["news", "cybersecurity"]
news-categories: ["cybersecurity"]
layout: "news"
draft: false
---

CISAは、複数のRuggedcom ROXデバイスに影響するCVE-2025-40948について警告しています。認証されたリモート攻撃者がルート権限で任意のファイルを読み取る可能性があります。バージョン2.17.1以降に更新してください。

{{< cyber-report severity="Medium" source="CISA" target="Siemens Ruggedcom ROXデバイス" cve="CVE-2025-40948" cvss="6.8" >}}

Siemens Ruggedcom ROXシリーズデバイスは、不適切なアクセス制御の脆弱性（CVE-2025-40948）の影響を受け、認証されたリモート攻撃者が基盤となるオペレーティングシステムからルート権限で任意のファイルを読み取ることができます。この欠陥は、WebサーバーのJSON-RPCインターフェースにおける入力の不適切な検証に起因し、引数インジェクションを可能にします。

{{< ad-banner >}}

以下の製品が脆弱です：RUGGEDCOM ROX MX5000、MX5000RE、RX1400、RX1500、RX1501、RX1510、RX1511、RX1512、RX1524、RX1536、RX5000。いずれもバージョン2.17.1より前のバージョンが対象です。Siemensはこの問題に対処するアップデートをリリースしており、直ちにパッチを適用することを推奨しています。

CVSS v3スコア6.8で、この脆弱性はMedium（中程度）の深刻度と評価されています。攻撃ベクトルはネットワークベースで、低い権限を必要とし、ユーザーの操作は不要です。これらのデバイスが展開されている重要インフラセクター（例：重要製造業）を考慮すると、悪用により重大な情報漏洩につながる可能性があります。

{{< netrunner-insight >}}

SOCアナリスト向け：環境内のRuggedcom ROXデバイス、特に信頼できないネットワークに公開されているものに優先的にパッチを適用してください。このエクスプロイトは認証を必要とするため、即時のリスクは軽減されますが、排除されるわけではありません。低権限アカウントを侵害した攻撃者は、完全なルートファイルアクセスにエスカレートする可能性があります。DevSecOpsチームはJSON-RPCエンドポイントの強化を検討し、ネットワークセグメンテーションによって露出を制限する必要があります。

{{< /netrunner-insight >}}

---

**[完全な記事を CISA で読む ›](https://www.cisa.gov/news-events/ics-advisories/icsa-26-134-02)**
