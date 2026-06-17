---
title: "CISA、Rockwell Automation CompactLogixコントローラのDoS脆弱性を警告"
date: "2026-06-17T11:46:16Z"
original_date: "2026-06-16T12:00:00"
lang: "ja"
translationKey: "cisa-warns-of-dos-vulnerabilities-in-rockwell-automation-compactlogix-controllers"
author: "NewsBot (Validated by Federico Sella)"
description: "Rockwell Automation CompactLogix 5370コントローラの複数の脆弱性により、サービス拒否攻撃が可能になる可能性があります。CVE-2025-11694はその脆弱性の1つです。"
original_url: "https://www.cisa.gov/news-events/ics-advisories/icsa-26-167-04"
source: "CISA"
severity: "High"
target: "Rockwell Automation CompactLogix 5370コントローラ"
cve: "CVE-2025-11694"
cvss: 7.5
kev: null
tags: ["news", "cybersecurity"]
news-categories: ["cybersecurity"]
layout: "news"
draft: false
---

Rockwell Automation CompactLogix 5370コントローラの複数の脆弱性により、サービス拒否攻撃が可能になる可能性があります。CVE-2025-11694はその脆弱性の1つです。

{{< cyber-report severity="High" source="CISA" target="Rockwell Automation CompactLogix 5370コントローラ" cve="CVE-2025-11694" cvss="7.5" >}}

CISAは、Rockwell Automation CompactLogix 5370コントローラ（L1、L2、L3）の脆弱性を詳細に説明した勧告（ICSA-26-167-04）を発表しました。これらの脆弱性には、整合性チェック値の不適切な検証や機密システム情報の漏洩が含まれ、攻撃者がサービス拒否状態を引き起こす可能性があります。この勧告は、V38.011より前のバージョンに影響します。

{{< ad-banner >}}

最も注目すべき脆弱性であるCVE-2025-11694は、CIPプロトコルにおけるシーケンス番号と送信元IPアドレスの検証欠如に関連しています。攻撃者は、Webインターフェースで表示される露出した接続IDを悪用してサービス拒否攻撃を実行し、軽微な障害を引き起こす可能性があります。この脆弱性のCVSS v3スコアは7.5です。

Rockwell Automationは、これらの問題を解決するためにバージョンV38.011に更新することを推奨しています。影響を受ける製品は、重要製造業セクター全体で世界中に展開されています。組織は、潜在的な運用中断を軽減するために、これらのコントローラのパッチ適用を優先すべきです。

{{< netrunner-insight >}}

SOCアナリストは、CompactLogixコントローラを標的とした異常なCIPトラフィックパターンや繰り返しの接続試行を監視してください。DevSecOpsエンジニアは、Webインターフェースが信頼できないネットワークに公開されていないことを確認し、ファームウェアをV38.011に速やかに更新してください。これは、適切なネットワークセグメンテーションとパッチ管理で緩和できる単純なDoSベクトルです。

{{< /netrunner-insight >}}

---

**[完全な記事を CISA で読む ›](https://www.cisa.gov/news-events/ics-advisories/icsa-26-167-04)**
