---
title: "日立エナジー ITT600 Explorer、libexpatの脆弱性によりDoS攻撃のリスク"
date: "2026-06-05T10:44:09Z"
original_date: "2026-06-04T12:00:00"
lang: "ja"
translationKey: "hitachi-energy-itt600-explorer-vulnerable-to-dos-via-libexpat-flaws"
author: "NewsBot (Validated by Federico Sella)"
description: "CISAは、日立エナジー ITT600 Explorerの2つの脆弱性がサービス拒否攻撃を許す可能性があると警告。影響を受けるのはバージョン2.1 SP6より前のもの。"
original_url: "https://www.cisa.gov/news-events/ics-advisories/icsa-26-155-02"
source: "CISA"
severity: "High"
target: "Hitachi Energy ITT600 Explorer"
cve: "CVE-2024-8176"
cvss: 7.5
kev: null
tags: ["news", "cybersecurity"]
news-categories: ["cybersecurity"]
layout: "news"
draft: false
---

CISAは、日立エナジー ITT600 Explorerの2つの脆弱性がサービス拒否攻撃を許す可能性があると警告。影響を受けるのはバージョン2.1 SP6より前のもの。

{{< cyber-report severity="High" source="CISA" target="Hitachi Energy ITT600 Explorer" cve="CVE-2024-8176" cvss="7.5" >}}

日立エナジーは、ITT600 Explorer製品における脆弱性を開示しました。特にバージョン2.1 SP6より前のバージョンに影響します。CVE-2024-8176およびCVE-2025-59375として特定されたこれらの欠陥は、制御されない再帰とリソースの制限なしの割り当てに関連しています。これらの問題は、サービス拒否（DoS）状態を引き起こすために悪用される可能性があります。

{{< ad-banner >}}

脆弱性は、IEC61850機能で使用されるlibexpatライブラリに存在します。ローカルアクセスを持つ攻撃者は、細工されたIEC61850メッセージを送信してスタックオーバーフローを引き起こし、DoSに加えてメモリ破損を引き起こす可能性があります。重要なのは、ITT600 Explorer製品のみが影響を受け、IEC 61850システムエンドポイントは影響を受けないことです。

CISAは、緩和策またはアップデートを直ちに適用することを推奨しています。この製品はエネルギー分野で世界中に展開されており、悪用されると重要インフラの運用が中断される可能性があります。影響を受けるバージョンを使用している組織は、パッチ適用を優先し、詳細な是正手順について勧告を確認する必要があります。

{{< netrunner-insight >}}

SOCアナリストは、悪用試みを示す異常なIEC61850トラフィックパターンを監視してください。DevSecOpsチームは、ITT600 Explorerをバージョン2.1 SP6以降に更新することを優先し、ツールへのローカルアクセスを制限するためにネットワークセグメンテーションを検討してください。CVSSスコア7.5とメモリ破損の可能性を考慮し、これを優先度の高いパッチとして扱ってください。

{{< /netrunner-insight >}}

---

**[完全な記事を CISA で読む ›](https://www.cisa.gov/news-events/ics-advisories/icsa-26-155-02)**
