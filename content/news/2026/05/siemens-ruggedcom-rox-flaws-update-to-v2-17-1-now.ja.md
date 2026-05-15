---
title: "Siemens Ruggedcom ROXの脆弱性：バージョン2.17.1に今すぐアップデートを"
date: "2026-05-15T09:41:40Z"
original_date: "2026-05-14T12:00:00"
lang: "ja"
translationKey: "siemens-ruggedcom-rox-flaws-update-to-v2-17-1-now"
author: "NewsBot (Validated by Federico Sella)"
description: "CISAは、Siemens Ruggedcom ROXのバージョン2.17.1以前における複数のサードパーティ製コンポーネントの脆弱性を警告しています。30件以上のCVEがリストされ、リモートコード実行のリスクも含まれています。直ちにアップデートするよう推奨されています。"
original_url: "https://www.cisa.gov/news-events/ics-advisories/icsa-26-134-16"
source: "CISA"
severity: "High"
target: "Siemens Ruggedcom ROXデバイス"
cve: "CVE-2019-13103"
cvss: null
kev: null
tags: ["news", "cybersecurity"]
news-categories: ["cybersecurity"]
layout: "news"
draft: false
---

CISAは、Siemens Ruggedcom ROXのバージョン2.17.1以前における複数のサードパーティ製コンポーネントの脆弱性を警告しています。30件以上のCVEがリストされ、リモートコード実行のリスクも含まれています。直ちにアップデートするよう推奨されています。

{{< cyber-report severity="High" source="CISA" target="Siemens Ruggedcom ROXデバイス" cve="CVE-2019-13103" >}}

Siemens Ruggedcom ROXのバージョン2.17.1より前のバージョンには、CISA勧告ICSA-26-134-16で開示された複数のサードパーティ製コンポーネントの脆弱性が含まれています。影響を受ける製品には、RUGGEDCOM ROX MX5000、MX5000RE、RX1400シリーズが含まれます。Siemensはこれらの問題を修正するアップデートをリリースしており、最新リリースへのアップグレードを強く推奨しています。

{{< ad-banner >}}

この勧告では、2019年から2025年にわたる30件以上のCVEがリストされており、CVE-2019-13103、CVE-2022-2347、CVE-2025-0395などが含まれています。具体的なCVSSスコアは提供されていませんが、脆弱性の範囲と古さから、攻撃対象領域が広いことが示唆されています。これらのCVEの多くはサードパーティ製コンポーネントに関連しており、リモートコード実行、サービス拒否、情報漏洩につながる可能性があります。

影響を受けるRuggedcom ROXデバイスを使用している組織は、特にデバイスが信頼できないネットワークにさらされている場合、パッチ適用を優先すべきです。これらの製品は産業用であるため、パッチ未適用のシステムは、ラテラルムーブメントや重要インフラの混乱に悪用される可能性があります。

{{< netrunner-insight >}}

これは、組み込みシステムにおける技術的負債の蓄積の典型的なケースです。SOCアナリストは、すべてのRuggedcom ROXインスタンスを棚卸しし、ファームウェアバージョンを確認する必要があります。DevSecOpsチームは、サードパーティ依存関係に対する自動CVEスキャンをCI/CDに統合する必要があります。CVSSスコアがないことは懸念材料です。最悪のケースを想定し、これらが重要であることが証明されるまでクリティカルとして扱ってください。

{{< /netrunner-insight >}}

---

**[完全な記事を CISA で読む ›](https://www.cisa.gov/news-events/ics-advisories/icsa-26-134-16)**
