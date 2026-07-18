---
title: "WordPressコアの新たな脆弱性「wp2shell」、認証なしで攻撃者がコードを実行可能に"
date: "2026-07-18T08:47:36Z"
original_date: "2026-07-17T21:20:10"
lang: "ja"
translationKey: "new-wp2shell-wordpress-core-flaw-lets-unauthenticated-attackers-run-code"
slug: "new-wp2shell-wordpress-core-flaw-lets-unauthenticated-attackers-run-code"
author: "NewsBot (Validated by Federico Sella)"
description: "匿名のHTTPリクエストによりWordPressサイトでコードが実行される可能性があります。このバグはコアに影響するため、素のインストールでも悪用可能です。パッチが適用されるまで、すべての6.9および7.0サイトが対象範囲でした。"
original_url: "https://thehackernews.com/2026/07/new-wp2shell-wordpress-core-flaw-lets.html"
source: "The Hacker News"
severity: "Critical"
target: "WordPressコア（バージョン6.9および7.0）"
cve: null
cvss: null
kev: null
tags: ["news", "cybersecurity"]
news-categories: ["cybersecurity"]
layout: "news"
draft: false
---

匿名のHTTPリクエストによりWordPressサイトでコードが実行される可能性があります。このバグはコアに影響するため、素のインストールでも悪用可能です。パッチが適用されるまで、すべての6.9および7.0サイトが対象範囲でした。

{{< cyber-report severity="Critical" source="The Hacker News" target="WordPressコア（バージョン6.9および7.0）" >}}

WordPressコアに、認証なしでのリモートコード実行の重大な脆弱性が発見され、バージョン6.9および7.0に影響します。wp2shellと名付けられたこの欠陥により、攻撃者は特別に細工されたHTTPリクエストを送信することで、対象サイト上で任意のコードを実行できます。特に、この脆弱性はコアソフトウェアに存在するため、プラグインが一切ない新しいWordPressインストールでも悪用可能です。

{{< ad-banner >}}

完全な技術的詳細と実証コードが公開され、2つの根本的な欠陥にCVE識別子が割り当てられています。また、永続オブジェクトキャッシュの状態も特定されており、特定の環境では悪用が複雑化する可能性があります。影響を受けるバージョンを実行しているすべてのサイトは、パッチが適用されるまでリスクがあると見なされていました。

管理者は直ちに最新のパッチ適用版にアップデートすることを推奨します。悪用の容易さとWordPressの広範な使用を考慮すると、この脆弱性はウェブセキュリティに重大な脅威をもたらします。組織はパッチ適用を優先し、ウェブアプリケーションファイアウォールのルールを見直して、悪用試行を検出・ブロックする必要があります。

{{< netrunner-insight >}}

これは、コアソフトウェアを認証なしの攻撃に対して強化すべきであるという典型的な例です。SOCアナリストは直ちにWordPress 6.9および7.0のインスタンスをスキャンし、パッチ適用状況を確認すべきです。DevSecOpsチームは、ランタイムアプリケーション自己保護（RASP）を実装し、wp-adminやwp-includesを標的とした異常なHTTPリクエストを監視するよう、この事例を注意喚起として捉えるべきです。

{{< /netrunner-insight >}}

---

**[完全な記事を The Hacker News で読む ›](https://thehackernews.com/2026/07/new-wp2shell-wordpress-core-flaw-lets.html)**
