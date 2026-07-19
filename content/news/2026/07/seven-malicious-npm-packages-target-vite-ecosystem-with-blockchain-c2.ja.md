---
title: "Viteエコシステムを標的にした7つの悪意あるnpmパッケージ、ブロックチェーンC2を利用"
date: "2026-07-19T09:03:59Z"
original_date: "2026-07-17T18:54:51"
lang: "ja"
translationKey: "seven-malicious-npm-packages-target-vite-ecosystem-with-blockchain-c2"
slug: "seven-malicious-npm-packages-target-vite-ecosystem-with-blockchain-c2"
author: "NewsBot (Validated by Federico Sella)"
description: "CheckmarxがViteVenomキャンペーンを発見。ブロックチェーンベースのC2インフラを使用し、Viteフロントエンドツールを標的とする7つの悪意あるnpmパッケージ経由でRATを配信。"
original_url: "https://thehackernews.com/2026/07/seven-malicious-vite-npm-packages-use.html"
source: "The Hacker News"
severity: "High"
target: "Viteフロントエンドツールエコシステム"
cve: null
cvss: null
kev: null
tags: ["news", "cybersecurity"]
news-categories: ["cybersecurity"]
layout: "news"
draft: false
---

CheckmarxがViteVenomキャンペーンを発見。ブロックチェーンベースのC2インフラを使用し、Viteフロントエンドツールを標的とする7つの悪意あるnpmパッケージ経由でRATを配信。

{{< cyber-report severity="High" source="The Hacker News" target="Viteフロントエンドツールエコシステム" >}}

Checkmarxのサイバーセキュリティ研究者は、Viteフロントエンドツールエコシステムを標的とした7つの悪意あるnpmパッケージのクラスターを特定しました。このキャンペーンはViteVenomと名付けられ、以前観測されたChainVeil作戦の拡大版であり、Tronネットワークにまたがる前例のない4層のブロックチェーンベースのコマンド＆コントロール（C2）インフラを利用しています。

{{< ad-banner >}}

これらの悪意あるパッケージは、侵害されたシステムにリモートアクセス型トロイの木馬（RAT）を配信し、攻撃者がデータを窃取して持続的なアクセスを維持することを可能にします。C2通信にブロックチェーンを使用することで、インフラが分散化され従来のシンクホール技術に耐性があるため、検出や停止がより困難になっています。

開発パイプラインでViteを使用している組織は、特定された悪意あるパッケージについて依存関係を直ちに監査し、厳格なパッケージ整合性チェックを実装する必要があります。このインシデントは、攻撃者が正当な開発ツールや分散型ネットワークを悪用して検出を回避する、ソフトウェアサプライチェーン攻撃の高度化が進んでいることを浮き彫りにしています。

{{< netrunner-insight >}}

SOCアナリストは、ブロックチェーンノードへの発信接続や異常なDNSクエリを監視することで、このC2手法を検出できます。DevSecOpsチームは、パッケージ署名を強制し、依存関係スキャンツールを使用して既知の悪意あるパッケージがビルドパイプラインに入る前にブロックする必要があります。

{{< /netrunner-insight >}}

---

**[完全な記事を The Hacker News で読む ›](https://thehackernews.com/2026/07/seven-malicious-vite-npm-packages-use.html)**
