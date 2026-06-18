---
title: "CISA、Rockwell FactoryTalk Analytics PavilionXの重大な認証バイパスを警告"
date: "2026-06-18T11:06:01Z"
original_date: "2026-06-16T12:00:00"
lang: "ja"
translationKey: "cisa-warns-of-critical-auth-bypass-in-rockwell-factorytalk-analytics-pavilionx"
author: "NewsBot (Validated by Federico Sella)"
description: "CISAがCVE-2025-14272に関する注意喚起。Rockwell Automation FactoryTalk Analytics PavilionX <7.01に影響し、重要製造環境で不正な特権操作を許す。"
original_url: "https://www.cisa.gov/news-events/ics-advisories/icsa-26-167-01"
source: "CISA"
severity: "High"
target: "Rockwell FactoryTalk Analytics PavilionX"
cve: "CVE-2025-14272"
cvss: null
kev: null
tags: ["news", "cybersecurity"]
news-categories: ["cybersecurity"]
layout: "news"
draft: false
---

CISAがCVE-2025-14272に関する注意喚起。Rockwell Automation FactoryTalk Analytics PavilionX <7.01に影響し、重要製造環境で不正な特権操作を許す。

{{< cyber-report severity="High" source="CISA" target="Rockwell FactoryTalk Analytics PavilionX" cve="CVE-2025-14272" >}}

CISAは、Rockwell Automation FactoryTalk Analytics PavilionXにおける認証欠落の脆弱性に関する勧告（ICSA-26-167-01）を公開しました。CVE-2025-14272として追跡されるこの欠陥は、バージョン7.01より前のものに影響し、認証されていない攻撃者がユーザーやロール管理などの特権操作を実行できるようにします。

{{< ad-banner >}}

この脆弱性は、APIエンドポイントにおける不適切な認可の実施に起因します。悪用に成功すると、影響を受けるシステムの完全な管理制御を奪取される可能性があります。Rockwell Automationはこの問題を修正するバージョン7.01をリリースしており、ユーザーは直ちにアップグレードするよう求められています。

この製品が世界中の重要製造セクターに展開されていることを考慮すると、運用の中断やデータ漏洩のリスクは重大です。組織はパッチ適用を優先し、アクセス制御を見直して悪用の可能性を軽減すべきです。

{{< netrunner-insight >}}

これは典型的な認証バイパスであり、優先度の高いパッチとして扱うべきです。SOCアナリストは、PavilionX環境における異常なAPI呼び出しや権限昇格を監視する必要があります。DevSecOpsチームは、バージョン7.01が展開され、ネットワークセグメンテーションによってこれらのエンドポイントへの露出が制限されていることを確認しなければなりません。

{{< /netrunner-insight >}}

---

**[完全な記事を CISA で読む ›](https://www.cisa.gov/news-events/ics-advisories/icsa-26-167-01)**
