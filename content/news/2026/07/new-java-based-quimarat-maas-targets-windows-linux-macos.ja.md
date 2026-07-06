---
title: "Javaベースの新しいQuimaRAT MaaSがWindows、Linux、macOSを標的に"
date: "2026-07-06T11:23:53Z"
original_date: "2026-07-06T08:13:33"
lang: "ja"
translationKey: "new-java-based-quimarat-maas-targets-windows-linux-macos"
slug: "new-java-based-quimarat-maas-targets-windows-linux-macos"
author: "NewsBot (Validated by Federico Sella)"
description: "QuimaRATは、クロスプラットフォームのJava RATで、マルウェア・アズ・ア・サービスとして販売され、Windows、Linux、macOSシステムを脅かしています。LevelBlueの研究者がそのサブスクリプションモデルと機能を詳述しています。"
original_url: "https://thehackernews.com/2026/07/new-java-based-quimarat-maas-built-to.html"
source: "The Hacker News"
severity: "High"
target: "Windows、Linux、macOSシステム"
cve: null
cvss: null
kev: null
tags: ["news", "cybersecurity"]
news-categories: ["cybersecurity"]
layout: "news"
draft: false
---

QuimaRATは、クロスプラットフォームのJava RATで、マルウェア・アズ・ア・サービスとして販売され、Windows、Linux、macOSシステムを脅かしています。LevelBlueの研究者がそのサブスクリプションモデルと機能を詳述しています。

{{< cyber-report severity="High" source="The Hacker News" target="Windows、Linux、macOSシステム" >}}

LevelBlueのサイバーセキュリティ研究者は、QuimaRATという名前の新しいJavaベースのリモートアクセス型トロイの木馬（RAT）を特定しました。これはWindows、Linux、macOS環境を標的にすることができます。このマルウェアは、マルウェア・アズ・ア・サービス（MaaS）モデルで販売されており、1ヶ月150ドルから生涯アクセス1,200ドルまでのサブスクリプション層があり、300ドルの層もあります。

{{< ad-banner >}}

QuimaRATのクロスプラットフォーム性はJavaによって実現されており、多様なオペレーティングシステムを侵害できるため、異種環境を持つ組織にとって多用途な脅威となっています。MaaSモデルは、スキルの低い脅威アクターの参入障壁を下げ、攻撃の頻度を増加させる可能性があります。

初期のレポートではQuimaRATの機能に関する具体的な技術的詳細は限られていますが、Javaベースのアーキテクチャは、キーロギング、スクリーンキャプチャ、ファイル流出などの一般的な手法を活用する可能性を示唆しています。組織は不審なJavaプロセスを監視し、アプリケーションの許可リストを実装してリスクを軽減する必要があります。

{{< netrunner-insight >}}

SOCアナリストにとって、QuimaRATのクロスプラットフォーム性は、検出ルールがWindows、Linux、macOSのエンドポイントをカバーしなければならないことを意味します。DevSecOpsチームはJavaランタイムの使用状況を確認し、署名されていないJavaアプリケーションの実行を制限することを検討すべきです。MaaSモデルを考慮すると、低スキルの攻撃者がこのRATを展開することが予想されるため、異常なネットワーク接続やプロセス動作のベースライン監視が重要です。

{{< /netrunner-insight >}}

---

**[完全な記事を The Hacker News で読む ›](https://thehackernews.com/2026/07/new-java-based-quimarat-maas-built-to.html)**
