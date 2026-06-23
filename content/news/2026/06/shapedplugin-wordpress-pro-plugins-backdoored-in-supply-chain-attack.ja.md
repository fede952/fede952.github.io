---
title: "ShapedPlugin WordPress Proプラグイン、サプライチェーン攻撃でバックドア仕掛けられる"
date: "2026-06-23T10:30:52Z"
original_date: "2026-06-22T18:00:48"
lang: "ja"
translationKey: "shapedplugin-wordpress-pro-plugins-backdoored-in-supply-chain-attack"
author: "NewsBot (Validated by Federico Sella)"
description: "複数のShapedPlugin WordPress Proプラグインがサプライチェーン攻撃により侵害され、公式リリースにバックドアコードが注入された。"
original_url: "https://thehackernews.com/2026/06/shapedplugin-wordpress-pro-plugins.html"
source: "The Hacker News"
severity: "High"
target: "ShapedPluginのWordPress Proプラグイン"
cve: null
cvss: null
kev: null
tags: ["news", "cybersecurity"]
news-categories: ["cybersecurity"]
layout: "news"
draft: false
---

複数のShapedPlugin WordPress Proプラグインがサプライチェーン攻撃により侵害され、公式リリースにバックドアコードが注入された。

{{< cyber-report severity="High" source="The Hacker News" target="ShapedPluginのWordPress Proプラグイン" >}}

ShapedPluginの複数のWordPressプラグインがサプライチェーン攻撃で侵害された。未知の脅威アクターが公式リリースチャネルを改ざんし、バックドアコードをプッシュした。Wordfenceによると、攻撃者はベンダーのビルドおよび配布パイプラインを侵害し、公式ライセンス更新チャネルを通じて配布されるProプラグインリリースにバックドアコードを注入した。

{{< ad-banner >}}

この攻撃は、サードパーティプラグインエコシステムに関連するリスクを浮き彫りにしており、単一の侵害されたベンダーが多数のウェブサイトに影響を与える可能性がある。ShapedPlugin Proプラグインのユーザーは、インストールの整合性を確認し、利用可能な最新のパッチ適用バージョンに更新することを推奨する。

Wordfenceはバックドアコードの詳細な分析を公開しており、侵害されたインストールを検出するために使用できる。組織はWordPress環境を確認し、不正アクセスや悪意のある活動の兆候がないか監視すべきである。

{{< netrunner-insight >}}

このサプライチェーン攻撃は、ソフトウェアサプライチェーンセキュリティ管理の重要性を強調している。SOCアナリストは異常なプラグイン更新動作を監視し、すべてのサードパーティコードに対して整合性チェックを実装することを検討すべきである。DevSecOpsチームは、同様の侵害を防ぐために厳格なパイプラインセキュリティとコード署名を徹底する必要がある。

{{< /netrunner-insight >}}

---

**[完全な記事を The Hacker News で読む ›](https://thehackernews.com/2026/06/shapedplugin-wordpress-pro-plugins.html)**
