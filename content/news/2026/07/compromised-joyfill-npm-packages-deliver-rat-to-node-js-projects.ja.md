---
title: "侵害された joyfill npm パッケージが Node.js プロジェクトに RAT を配信"
date: "2026-07-29T09:34:53Z"
original_date: "2026-07-29T04:20:57"
lang: "ja"
translationKey: "compromised-joyfill-npm-packages-deliver-rat-to-node-js-projects"
slug: "compromised-joyfill-npm-packages-deliver-rat-to-node-js-projects"
author: "NewsBot (Validated by Federico Sella)"
description: "@joyfill/layouts と @joyfill/components のベータ版には、暗号化されたコードを解決してリモートアクセス型トロイの木馬を展開するインポート時 JavaScript インプラントが含まれています。"
original_url: "https://thehackernews.com/2026/07/two-compromised-joyfill-npm-packages.html"
source: "The Hacker News"
severity: "High"
target: "joyfill パッケージを使用する Node.js 開発者"
cve: null
cvss: null
kev: null
tags: ["news", "cybersecurity"]
news-categories: ["cybersecurity"]
layout: "news"
draft: false
---

@joyfill/layouts と @joyfill/components のベータ版には、暗号化されたコードを解決してリモートアクセス型トロイの木馬を展開するインポート時 JavaScript インプラントが含まれています。

{{< cyber-report severity="High" source="The Hacker News" target="joyfill パッケージを使用する Node.js 開発者" >}}

@joyfill 名前空間の 2 つの npm パッケージ、@joyfill/layouts バージョン 0.1.2-2773.beta.0 と @joyfill/components バージョン 4.0.0-rc24-2773-beta.4 が侵害されました。これらのベータリリースには、暗号化されたコードを解決するインポート時 JavaScript インプラントが含まれており、最終的に DEV#POPPER マルウェアファミリーに関連するリモートアクセス型トロイの木馬 (RAT) を配信します。

{{< ad-banner >}}

悪意のあるコードは、パッケージが Node.js プロジェクトにインポートされると実行され、攻撃者に侵害されたシステムへのリモートアクセスを提供します。この攻撃は、特に監視が少ない可能性のあるベータ版やリリース候補版を介した npm エコシステムを標的としたサプライチェーン攻撃の継続的なリスクを浮き彫りにしています。

これらの特定のバージョンを使用した開発者は、直ちに認証情報をローテーションし、侵害の痕跡をスキャンし、依存関係ツリーを確認して他の不審なパッケージがないか確認する必要があります。npm レジストリは悪意のあるバージョンを削除した可能性がありますが、既存のインストールは依然として脅威です。

{{< netrunner-insight >}}

このインシデントは、プレリリースパッケージを精査し、依存関係の整合性チェックを実装することの重要性を強調しています。SOC アナリストは Node.js アプリケーションからの異常な送信接続を監視し、DevSecOps チームは厳格なバージョン固定を実施し、npm audit や SCA スキャナーなどのツールを使用して既知の悪意のあるパッケージを検出する必要があります。

{{< /netrunner-insight >}}

---

**[完全な記事を The Hacker News で読む ›](https://thehackernews.com/2026/07/two-compromised-joyfill-npm-packages.html)**
