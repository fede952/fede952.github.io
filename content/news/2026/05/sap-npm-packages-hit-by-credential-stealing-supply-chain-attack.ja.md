---
title: "SAP npmパッケージが認証情報を盗むサプライチェーン攻撃の標的に"
date: "2026-05-03T08:51:39Z"
original_date: "2026-04-29T16:26:00"
lang: "ja"
translationKey: "sap-npm-packages-hit-by-credential-stealing-supply-chain-attack"
author: "NewsBot (Validated by Federico Sella)"
description: "「Mini Shai-Hulud」と名付けられたキャンペーンが、SAP関連のnpmパッケージを標的に認証情報を盗むマルウェアを展開し、複数のパッケージに影響を与えています。複数の企業の研究者がサプライチェーンリスクを警告しています。"
original_url: "https://thehackernews.com/2026/04/sap-npm-packages-compromised-by-mini.html"
source: "The Hacker News"
severity: "High"
target: "SAP関連のnpmパッケージ"
cve: null
cvss: null
kev: null
tags: ["news", "cybersecurity"]
news-categories: ["cybersecurity"]
layout: "news"
draft: false
---

「Mini Shai-Hulud」と名付けられたキャンペーンが、SAP関連のnpmパッケージを標的に認証情報を盗むマルウェアを展開し、複数のパッケージに影響を与えています。複数の企業の研究者がサプライチェーンリスクを警告しています。

{{< cyber-report severity="High" source="The Hacker News" target="SAP関連のnpmパッケージ" >}}

サイバーセキュリティ研究者らは、SAP関連のnpmパッケージを標的にしたサプライチェーン攻撃キャンペーンを発見しました。「Mini Shai-Hulud」と名付けられたこのキャンペーンは、侵害されたパッケージを通じて認証情報を盗むマルウェアを展開していると、Aikido Security、Onapsis、OX Security、SafeDep、Socket、StepSecurity、Wizの各社が報告しています。

{{< ad-banner >}}

この攻撃はSAPに関連する複数のnpmパッケージに影響を与えていますが、具体的なパッケージ名やバージョンは公開されていません。マルウェアは認証情報を盗むように設計されており、攻撃者に機密性の高いSAP環境や下流システムへのアクセスを与える可能性があります。

このインシデントは、特にSAPのようなエンタープライズ向け重要プラットフォームにおけるソフトウェアサプライチェーンへの脅威の高まりを浮き彫りにしています。影響を受けるパッケージを使用している組織は、依存関係を監査し、侵害された可能性のある認証情報をローテーションするよう推奨されます。

{{< netrunner-insight >}}

SOCアナリストやDevSecOpsチームにとって、この攻撃はnpmパッケージに対する厳格な依存関係スキャンと整合性チェックの必要性を強調しています。SAP関連システムからの異常な送信接続を監視し、認証情報の盗難を検出するためにランタイムアプリケーション自己保護（RASP）の導入を検討してください。侵害された可能性のあるパッケージを通じて露出した認証情報は直ちにすべてローテーションしてください。

{{< /netrunner-insight >}}

---

**[完全な記事を The Hacker News で読む ›](https://thehackernews.com/2026/04/sap-npm-packages-compromised-by-mini.html)**
