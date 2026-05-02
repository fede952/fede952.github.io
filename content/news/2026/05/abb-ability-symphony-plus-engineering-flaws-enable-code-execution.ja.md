---
title: "ABB Ability Symphony Plus Engineeringの欠陥によりコード実行が可能に"
date: "2026-05-02T08:20:38Z"
original_date: "2026-04-30T12:00:00"
lang: "ja"
translationKey: "abb-ability-symphony-plus-engineering-flaws-enable-code-execution"
author: "NewsBot (Validated by Federico Sella)"
description: "CISAは、ABB Ability Symphony Plus Engineeringにおける古いPostgreSQLに起因する脆弱性を警告しており、影響を受けるシステム上で任意のコード実行を許す可能性がある。"
original_url: "https://www.cisa.gov/news-events/ics-advisories/icsa-26-120-06"
source: "CISA"
severity: "High"
target: "ABB Ability Symphony Plus Engineering"
cve: "CVE-2023-5869"
cvss: 8.8
kev: null
tags: ["news", "cybersecurity"]
news-categories: ["cybersecurity"]
layout: "news"
draft: false
---

CISAは、ABB Ability Symphony Plus Engineeringにおける古いPostgreSQLに起因する脆弱性を警告しており、影響を受けるシステム上で任意のコード実行を許す可能性がある。

{{< cyber-report severity="High" source="CISA" target="ABB Ability Symphony Plus Engineering" cve="CVE-2023-5869" cvss="8.8" >}}

CISAは勧告（ICSA-26-120-06）を発表し、ABB Ability Symphony Plus Engineeringにおける複数の脆弱性を詳細に説明している。これらはPostgreSQLバージョン13.11以前の使用に起因し、整数オーバーフロー、SQLインジェクション、TOCTOU競合状態、権限低下エラーなどの欠陥を含み、認証された攻撃者がシステム上で任意のコードを実行する可能性がある。

{{< ad-banner >}}

影響を受けるバージョンはAbility Symphony Plus 2.2から2.4 SP2 RU1までに及ぶ。これらの脆弱性は、化学、重要製造、エネルギー、上下水道などの重要インフラ分野で世界中に展開されている製品であることから、特に懸念される。

最も注目すべき脆弱性であるCVE-2023-5869はCVSSスコア8.8であり、認証されたPostgreSQLユーザーが細工したデータを送信することでトリガーされる整数オーバーフローを含む。悪用に成功するとシステム全体が侵害される可能性があり、即時のパッチ適用の必要性が強調される。

{{< netrunner-insight >}}

この勧告は、OT環境における古い依存関係のリスクを浮き彫りにしている。SOCアナリストはABB Symphony Plusインスタンスの資産発見を優先し、PostgreSQLが13.11以降に更新されていることを確認すべきである。DevSecOpsチームは、産業用制御システムのCI/CDパイプラインに依存関係スキャンを統合し、このような継承された脆弱性を早期に発見する必要がある。

{{< /netrunner-insight >}}

---

**[完全な記事を CISA で読む ›](https://www.cisa.gov/news-events/ics-advisories/icsa-26-120-06)**
