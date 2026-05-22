---
title: "CISA、ABB B&R Automation Runtimeのセッションハイジャックを許す脆弱性を警告"
date: "2026-05-22T10:20:32Z"
original_date: "2026-05-21T12:00:00"
lang: "ja"
translationKey: "cisa-warns-of-abb-b-r-automation-runtime-flaws-allowing-session-hijack"
author: "NewsBot (Validated by Federico Sella)"
description: "ABB B&R Automation Runtime 6.4未満の複数の脆弱性により、攻撃者がセッションを乗っ取ったりコードを実行したりする可能性があります。CISAの勧告ICSA-26-141-04で修正が詳述されています。"
original_url: "https://www.cisa.gov/news-events/ics-advisories/icsa-26-141-04"
source: "CISA"
severity: "Medium"
target: "ABB B&R Automation Runtime"
cve: "CVE-2025-3449"
cvss: 6.1
kev: null
tags: ["news", "cybersecurity"]
news-categories: ["cybersecurity"]
layout: "news"
draft: false
---

ABB B&R Automation Runtime 6.4未満の複数の脆弱性により、攻撃者がセッションを乗っ取ったりコードを実行したりする可能性があります。CISAの勧告ICSA-26-141-04で修正が詳述されています。

{{< cyber-report severity="Medium" source="CISA" target="ABB B&R Automation Runtime" cve="CVE-2025-3449" cvss="6.1" >}}

CISAは、産業オートメーションで使用されるソフトウェアプラットフォームであるABB B&R Automation Runtimeの複数の脆弱性を詳述した勧告ICSA-26-141-04を公開しました。B&Rの内部セキュリティ分析によって特定されたこれらの欠陥は、バージョン6.4未満に影響し、CVE-2025-3449（予測可能なセッション識別子）、CVE-2025-3448（クロスサイトスクリプティング）、CVE-2025-11498（CSVファイル内の数式要素の不適切な無効化）を含みます。認証されていない攻撃者がこれらを悪用して、リモートセッションを乗っ取ったり、ユーザーのブラウザのコンテキストでコードを実行したりする可能性があります。

{{< ad-banner >}}

最も深刻な脆弱性であるCVE-2025-3449は、System Diagnostic Manager（SDM）コンポーネントに存在し、CVSS v3スコアは6.1です。これにより、認証されていないネットワークベースの攻撃者が、予測可能な数値や識別子の生成により、既に確立されたセッションを乗っ取ることができます。SDMはAutomation Runtime 6ではデフォルトで無効になっており、露出を減らしていますが、組織は明示的に必要な場合を除き、SDMがオフのままであることを確認する必要があります。

ABBはこれらの問題を修正するためにAutomation Runtimeバージョン6.4をリリースしました。この製品がエネルギー分野で世界中に展開されていることを考慮し、CISAはオペレーターに速やかにアップデートを適用するよう促しています。勧告では、悪用に成功するとリモートコード実行やセッション乗っ取りにつながる可能性があり、産業用制御環境に重大なリスクをもたらすと指摘しています。

{{< netrunner-insight >}}

SOCアナリスト向け：特にSDMが有効になっているAutomation Runtimeインスタンスのパッチ適用を優先してください。予測可能なセッションIDの欠陥（CVE-2025-3449）は、ネットワーク経由で簡単に悪用可能です。DevSecOpsチームは、SDMが本番環境で無効のままであることを確認し、公開されたインスタンスが信頼できないネットワークから到達可能でないことを検証してください。異常なセッションアクティビティを検出シグナルとして監視してください。

{{< /netrunner-insight >}}

---

**[完全な記事を CISA で読む ›](https://www.cisa.gov/news-events/ics-advisories/icsa-26-141-04)**
