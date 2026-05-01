---
title: "CISA、ABB AWINゲートウェイの再起動とデータ漏洩を許す脆弱性を警告"
date: "2026-05-01T08:55:30Z"
original_date: "2026-04-30T12:00:00"
lang: "ja"
translationKey: "cisa-warns-of-abb-awin-gateway-flaws-allowing-reboot-data-leak"
author: "NewsBot (Validated by Federico Sella)"
description: "ABB AWINゲートウェイには、攻撃者がデバイスを再起動したりシステム構成を抽出したりできる脆弱性があります。CISA勧告ICSA-26-120-05はCVE-2025-13777と修正を詳述しています。"
original_url: "https://www.cisa.gov/news-events/ics-advisories/icsa-26-120-05"
source: "CISA"
severity: "High"
target: "ABB AWINゲートウェイ"
cve: "CVE-2025-13777"
cvss: 8.3
kev: null
tags: ["news", "cybersecurity"]
news-categories: ["cybersecurity"]
layout: "news"
draft: false
---

ABB AWINゲートウェイには、攻撃者がデバイスを再起動したりシステム構成を抽出したりできる脆弱性があります。CISA勧告ICSA-26-120-05はCVE-2025-13777と修正を詳述しています。

{{< cyber-report severity="High" source="CISA" target="ABB AWINゲートウェイ" cve="CVE-2025-13777" cvss="8.3" >}}

CISAは、ABB AWINゲートウェイの複数の脆弱性を詳述した勧告ICSA-26-120-05を公開しました。これらの脆弱性には、キャプチャリプレイによる認証バイパスや重要な機能に対する認証欠如が含まれており、認証されていない攻撃者がリモートでデバイスを再起動したり、機密性の高いシステム構成データを照会したりする可能性があります。脆弱性は、GW100 rev.2およびGW120ハードウェア上で動作するAWINファームウェアバージョン2.0-0、2.0-1、1.2-0、1.2-1に影響します。

{{< ad-banner >}}

最も深刻な問題はCVE-2025-13777として追跡されており、認証されていないクエリによって機密詳細を含むシステム構成が漏洩する可能性があります。勧告ではCVSS v3基本スコア8.3が割り当てられ、深刻度が高いことを示しています。ABBはこれらの脆弱性を修正するためにGW100 rev.2向けファームウェアバージョン2.1-0をリリースしました。影響を受けるゲートウェイを使用している組織は、直ちにアップデートを適用するよう求められています。

これらの脆弱性は、世界中に展開されている重要な製造部門の資産に影響を与えます。認証なしでのリモート悪用の可能性を考慮すると、これらの欠陥は運用技術環境に重大なリスクをもたらします。CISAは、ユーザーが完全な勧告を確認し、ネットワークセグメンテーションや影響を受けるデバイスへのアクセス制限などの緩和策を実施することを推奨しています。

{{< netrunner-insight >}}

SOCアナリスト向け：ABBゲートウェイへの不正な再起動や異常なクエリを監視してください。これらは悪用の低ノイズ指標です。DevSecOpsチームはファームウェア2.1-0へのパッチ適用を優先し、厳格なネットワークアクセス制御を実施すべきです。これらの脆弱性は認証を必要とせず、リモートから悪用される可能性があります。

{{< /netrunner-insight >}}

---

**[完全な記事を CISA で読む ›](https://www.cisa.gov/news-events/ics-advisories/icsa-26-120-05)**
