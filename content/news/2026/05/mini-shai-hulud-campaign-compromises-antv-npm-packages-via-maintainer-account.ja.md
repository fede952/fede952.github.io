---
title: "Mini Shai-Huludキャンペーン、メンテナーアカウント経由で@antv npmパッケージを侵害"
date: "2026-05-19T10:37:35Z"
original_date: "2026-05-19T04:54:17"
lang: "ja"
translationKey: "mini-shai-hulud-campaign-compromises-antv-npm-packages-via-maintainer-account"
author: "NewsBot (Validated by Federico Sella)"
description: "攻撃者が@antvのメンテナーアカウント「atool」を侵害し、週間ダウンロード数110万のecharts-for-reactを含む悪意のあるnpmパッケージをプッシュ。進行中のMini Shai-Huludサプライチェーン攻撃の波の一環。"
original_url: "https://thehackernews.com/2026/05/mini-shai-hulud-pushes-malicious-antv.html"
source: "The Hacker News"
severity: "High"
target: "@antv npmエコシステム"
cve: null
cvss: null
kev: null
tags: ["news", "cybersecurity"]
news-categories: ["cybersecurity"]
layout: "news"
draft: false
---

攻撃者が@antvのメンテナーアカウント「atool」を侵害し、週間ダウンロード数110万のecharts-for-reactを含む悪意のあるnpmパッケージをプッシュ。進行中のMini Shai-Huludサプライチェーン攻撃の波の一環。

{{< cyber-report severity="High" source="The Hacker News" target="@antv npmエコシステム" >}}

サイバーセキュリティ研究者は、@antv npmエコシステムを標的とした新たなソフトウェアサプライチェーン攻撃キャンペーンを特定した。攻撃者はnpmメンテナーアカウント「atool」を侵害し、Apache ECharts用の広く使われているReactラッパーで週間ダウンロード数約110万のecharts-for-reactを含む複数のパッケージの悪意あるバージョンを公開した。

{{< ad-banner >}}

このキャンペーンは、以前に他のオープンソースエコシステムを標的とした進行中のMini Shai-Hulud攻撃の波の一部である。侵害されたパッケージには、機密データを外部に流出させたり、開発環境にバックドアを仕掛けるように設計された悪意のあるコードが含まれている可能性が高い。

@antvパッケージを使用している組織は、依存関係に侵害の兆候がないか直ちに監査し、認証情報をローテーションし、ロックファイルの最近の変更を確認すべきである。影響を受けるパッケージの全容と正確なペイロードは調査中である。

{{< netrunner-insight >}}

この攻撃は、パッケージの整合性検証、メンテナーアカウントへの多要素認証、自動化された依存関係スキャンなどのサプライチェーンセキュリティ対策の重要性を浮き彫りにしている。SOCアナリストはビルドパイプラインからの異常な送信トラフィックの監視を優先すべきであり、DevSecOpsチームはパッケージ公開アカウントに対する厳格なアクセス制御を実施しなければならない。

{{< /netrunner-insight >}}

---

**[完全な記事を The Hacker News で読む ›](https://thehackernews.com/2026/05/mini-shai-hulud-pushes-malicious-antv.html)**
