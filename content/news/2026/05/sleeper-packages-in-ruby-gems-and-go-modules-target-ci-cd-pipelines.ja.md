---
title: "Ruby GemとGo ModuleにおけるスリーパーパッケージがCI/CDパイプラインを標的に"
date: "2026-05-04T09:17:53Z"
original_date: "2026-05-01T09:43:00"
lang: "ja"
translationKey: "sleeper-packages-in-ruby-gems-and-go-modules-target-ci-cd-pipelines"
author: "NewsBot (Validated by Federico Sella)"
description: "攻撃者はスリーパーパッケージを使用して悪意のあるペイロードを配信し、認証情報の窃取、GitHub Actionsの改ざん、SSH永続化をソフトウェアサプライチェーン攻撃で行います。"
original_url: "https://thehackernews.com/2026/05/poisoned-ruby-gems-and-go-modules.html"
source: "The Hacker News"
severity: "High"
target: "CI/CDパイプラインとソフトウェアサプライチェーン"
cve: null
cvss: null
kev: null
tags: ["news", "cybersecurity"]
news-categories: ["cybersecurity"]
layout: "news"
draft: false
---

攻撃者はスリーパーパッケージを使用して悪意のあるペイロードを配信し、認証情報の窃取、GitHub Actionsの改ざん、SSH永続化をソフトウェアサプライチェーン攻撃で行います。

{{< cyber-report severity="High" source="The Hacker News" target="CI/CDパイプラインとソフトウェアサプライチェーン" >}}

新たなソフトウェアサプライチェーン攻撃キャンペーンが確認され、スリーパーパッケージを経由して悪意のあるペイロードを後続的にプッシュし、認証情報の窃取、GitHub Actionsの改ざん、SSH永続化を可能にしています。この活動はGitHubアカウント「BufferZoneCorp」に起因しており、悪意のあるRuby GemとGo Moduleに関連するリポジトリセットを公開しています。

{{< ad-banner >}}

この攻撃は、当初は無害に見えるパッケージが後に悪意のあるアップデートを受け取る「スリーパー」または「トロイの木馬化」パッケージと呼ばれる手法を利用しています。CI/CD環境にインストールされると、ペイロードは認証情報を盗み、GitHub Actionsワークフローを改ざんし、永続的なSSHアクセスを確立し、開発パイプラインに重大な脅威をもたらします。

信頼できないソースからのRuby GemやGo Moduleを使用している組織は、依存関係を監査し、不審なリポジトリ活動を監視する必要があります。このキャンペーンは、開発者インフラを標的としたサプライチェーン攻撃の高度化の進化を示しています。

{{< netrunner-insight >}}

このキャンペーンは、CI/CDパイプラインにおける厳格な依存関係の固定と整合性検証の必要性を強調しています。SOCアナリストは、異常なGitHub Actionsの変更やSSHキーの追加を監視すべきであり、DevSecOpsエンジニアは最小権限アクセスを実装し、爆発半径を制限するためにエフェメラルビルド環境の使用を検討すべきです。

{{< /netrunner-insight >}}

---

**[完全な記事を The Hacker News で読む ›](https://thehackernews.com/2026/05/poisoned-ruby-gems-and-go-modules.html)**
