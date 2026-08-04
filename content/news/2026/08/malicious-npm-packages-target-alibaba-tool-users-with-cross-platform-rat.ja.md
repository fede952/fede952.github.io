---
title: "悪意のあるnpmパッケージがAlibabaツールのユーザーを標的にし、クロスプラットフォームRATを配布"
date: "2026-08-04T09:40:19Z"
original_date: "2026-08-03T18:43:53"
lang: "ja"
translationKey: "malicious-npm-packages-target-alibaba-tool-users-with-cross-platform-rat"
slug: "malicious-npm-packages-target-alibaba-tool-users-with-cross-platform-rat"
author: "NewsBot (Validated by Federico Sella)"
description: "研究者らは、'lib-mtop'を含む18個の悪意のあるnpmパッケージを発見しました。これらは、標的型サプライチェーン攻撃でAlibaba開発者ツールのユーザーにクロスプラットフォームRATを配信します。"
original_url: "https://thehackernews.com/2026/08/18-malicious-npm-packages-deliver-cross.html"
source: "The Hacker News"
severity: "High"
target: "Alibaba開発者ツールのユーザー"
cve: null
cvss: null
kev: null
tags: ["news", "cybersecurity"]
news-categories: ["cybersecurity"]
layout: "news"
draft: false
---

研究者らは、'lib-mtop'を含む18個の悪意のあるnpmパッケージを発見しました。これらは、標的型サプライチェーン攻撃でAlibaba開発者ツールのユーザーにクロスプラットフォームRATを配信します。

{{< cyber-report severity="High" source="The Hacker News" target="Alibaba開発者ツールのユーザー" >}}

サイバーセキュリティ研究者らは、Alibaba開発者ツールのユーザーを標的にするように設計された、18個の新しい悪意のあるnpmパッケージを特定しました。この攻撃は、高度で標的型のソフトウェアサプライチェーンキャンペーンの一部であり、中国語圏の環境に特化していることから、高度な偵察とローカライゼーションが行われていることを示しています。

{{< ad-banner >}}

パッケージの1つである'lib-mtop'は、スコープなしのパッケージで、プライベートなAlibabaパッケージと同じ名前を共有しており、古典的なタイポスクワッティング手法です。これは、攻撃者が正規のパッケージの代わりに悪意のあるパッケージを誤ってインストールする開発者を欺こうとしていることを示唆しており、それによって開発環境への足がかりを得ようとしています。

悪意のあるパッケージは、被害者にクロスプラットフォームのリモートアクセストロイの木馬（RAT）を配信し、攻撃者に侵害されたシステムへのリモート制御を提供する可能性があります。RATのクロスプラットフォーム性は、幅広いオペレーティングシステムに影響を与えるように設計されていることを示しており、攻撃の潜在的な影響を増大させています。

{{< netrunner-insight >}}

この攻撃は、特にプライベートまたは内部パッケージを使用する場合に、パッケージの信頼性を検証することの重要性を強調しています。SOCアナリストとDevSecOpsエンジニアは、ロックファイルの使用やパッケージの整合性の検証など、厳格なパッケージの来歴チェックを実装し、開発マシンからの予期しないネットワーク接続を監視する必要があります。さらに、タイポスクワッティング攻撃を防ぐために、許可リスト付きのプライベートレジストリの使用を検討してください。

{{< /netrunner-insight >}}

---

**[完全な記事を The Hacker News で読む ›](https://thehackernews.com/2026/08/18-malicious-npm-packages-deliver-cross.html)**
