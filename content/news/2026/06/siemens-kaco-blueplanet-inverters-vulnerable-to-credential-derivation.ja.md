---
title: "Siemens KACO Blueplanet インバーターに認証情報導出の脆弱性"
date: "2026-06-10T10:51:15Z"
original_date: "2026-06-09T12:00:00"
lang: "ja"
translationKey: "siemens-kaco-blueplanet-inverters-vulnerable-to-credential-derivation"
author: "NewsBot (Validated by Federico Sella)"
description: "KACO blueplanet インバーターの複数の脆弱性により、攻撃者がシリアル番号から認証情報を導出し、不正アクセスを得る可能性があります。Siemens はアップデートを推奨しています。"
original_url: "https://www.cisa.gov/news-events/ics-advisories/icsa-26-160-02"
source: "CISA"
severity: "High"
target: "Siemens KACO Blueplanet インバーター"
cve: null
cvss: null
kev: null
tags: ["news", "cybersecurity"]
news-categories: ["cybersecurity"]
layout: "news"
draft: false
---

KACO blueplanet インバーターの複数の脆弱性により、攻撃者がシリアル番号から認証情報を導出し、不正アクセスを得る可能性があります。Siemens はアップデートを推奨しています。

{{< cyber-report severity="High" source="CISA" target="Siemens KACO Blueplanet インバーター" >}}

CISA は、Siemens KACO blueplanet インバーターの複数の脆弱性を詳述した勧告 (ICSA-26-160-02) を発表しました。これらの欠陥により、攻撃者はデバイスのシリアル番号から認証情報を導出し、それを悪用してインバーターに不正アクセスする可能性があります。

{{< ad-banner >}}

この勧告は、blueplanet 100 NX3 M8、100 TL3 GEN2、105 TL3 など、広範囲の影響を受けるモデルを対象としており、バージョンは all/* または 6.1.4.9 未満の特定のファームウェアバージョンとされています。KACO new energy GmbH は一部の製品に対してアップデートをリリースし、他の製品については修正を準備中であり、パッチがまだ利用できない場合には対策を推奨しています。

勧告には CVE 識別子や CVSS スコアは提供されていません。これらの脆弱性は、リモートから悪用されて不正なデバイスアクセスを引き起こす可能性があるため、深刻と見なされており、太陽エネルギーインフラに影響を及ぼす可能性があります。

{{< netrunner-insight >}}

SOC アナリストと DevSecOps エンジニアにとって、この勧告は IoT/OT デバイスにおけるハードコードされた、または導出可能な認証情報のリスクを強調しています。影響を受ける KACO インバーターを直ちに特定し、利用可能な場合はファームウェアアップデートを適用してください。パッチ未適用のユニットについては、ネットワークセグメンテーションを実装し、暫定的な緩和策として異常なアクセス試行を監視してください。

{{< /netrunner-insight >}}

---

**[完全な記事を CISA で読む ›](https://www.cisa.gov/news-events/ics-advisories/icsa-26-160-02)**
