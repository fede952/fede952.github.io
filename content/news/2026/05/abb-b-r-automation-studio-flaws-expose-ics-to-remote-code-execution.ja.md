---
title: "ABB B&R Automation Studioの脆弱性によりICSがリモートコード実行にさらされる"
date: "2026-05-23T09:00:47Z"
original_date: "2026-05-21T12:00:00"
lang: "ja"
translationKey: "abb-b-r-automation-studio-flaws-expose-ics-to-remote-code-execution"
author: "NewsBot (Validated by Federico Sella)"
description: "CISAはABB B&R Automation Studioにおける25件の脆弱性を警告。CVSS 9.8の重大なバグにより、不正アクセスやリモートコード実行が可能になる可能性がある。"
original_url: "https://www.cisa.gov/news-events/ics-advisories/icsa-26-141-03"
source: "CISA"
severity: "Critical"
target: "ABB B&R Automation Studio"
cve: "CVE-2025-6965"
cvss: 9.8
kev: null
tags: ["news", "cybersecurity"]
news-categories: ["cybersecurity"]
layout: "news"
draft: false
---

CISAはABB B&R Automation Studioにおける25件の脆弱性を警告。CVSS 9.8の重大なバグにより、不正アクセスやリモートコード実行が可能になる可能性がある。

{{< cyber-report severity="Critical" source="CISA" target="ABB B&R Automation Studio" cve="CVE-2025-6965" cvss="9.8" >}}

CISAは、ABB B&R Automation Studioのバージョン6.5未満およびバージョン6.5に影響する複数の脆弱性に関する勧告を公開した。この勧告には、CVE-2025-6965、CVE-2025-3277、CVE-2023-7104などを含む25件のCVEがリストされている。これらの脆弱性は、古いサードパーティコンポーネントに起因し、ヒープベースのバッファオーバーフロー、範囲外書き込み、解放後使用、不適切な入力検証などの問題を含む。

{{< ad-banner >}}

ABBはテスト中に悪用の観測は報告していないが、これらの脆弱性は不正アクセス、データ漏洩、またはリモートコード実行の攻撃ベクトルとなる可能性がある。最も深刻なCVEはCVSS v3スコア9.8で、重大な深刻度を示している。影響を受ける製品は産業オートメーションおよび制御システムで使用されており、脅威アクターにとって魅力的な標的となっている。

ABBは古いサードパーティコンポーネントを置き換えるアップデートをリリースした。B&R Automation Studioを使用している組織は、直ちにアップデートを適用することが推奨される。これらの脆弱性の重大性とリモート悪用の可能性を考慮し、資産所有者はパッチ適用を優先し、侵害の兆候を監視すべきである。

{{< netrunner-insight >}}

SOCアナリストおよびDevSecOpsエンジニアにとって、この勧告はICSソフトウェアにおけるサードパーティ依存関係のリスクを浮き彫りにしている。25件ものCVEの数は、コンポーネント管理における体系的な問題を示唆している。B&R Automation Studioのインスタンスのインベントリを優先し、ベンダーのアップデートを適用すること。さらに、ICSネットワークをセグメント化して露出を制限し、悪用試みを示唆する異常な動作を監視するためのモニタリングを実装すること。

{{< /netrunner-insight >}}

---

**[完全な記事を CISA で読む ›](https://www.cisa.gov/news-events/ics-advisories/icsa-26-141-03)**
