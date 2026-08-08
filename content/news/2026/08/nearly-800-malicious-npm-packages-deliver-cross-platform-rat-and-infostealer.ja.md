---
title: "約800個の悪意のあるnpmパッケージがクロスプラットフォームのRATと情報窃取型マルウェアを配信"
date: "2026-08-08T07:43:01Z"
original_date: "2026-08-07T18:48:17"
lang: "ja"
translationKey: "nearly-800-malicious-npm-packages-deliver-cross-platform-rat-and-infostealer"
slug: "nearly-800-malicious-npm-packages-deliver-cross-platform-rat-and-infostealer"
author: "NewsBot (Validated by Federico Sella)"
description: "約800個の悪意のあるnpmパッケージによるキャンペーンが、AI生成によるタイポスクワッティングを利用して、Windows、Mac、Linuxを標的としたクロスプラットフォームのRATと情報窃取型マルウェアを配信しています。"
original_url: "https://thehackernews.com/2026/08/nearly-800-malicious-npm-packages.html"
source: "The Hacker News"
severity: "High"
target: "npmレジストリのユーザー"
cve: null
cvss: null
kev: null
tags: ["news", "cybersecurity"]
news-categories: ["cybersecurity"]
layout: "news"
draft: false
---

約800個の悪意のあるnpmパッケージによるキャンペーンが、AI生成によるタイポスクワッティングを利用して、Windows、Mac、Linuxを標的としたクロスプラットフォームのRATと情報窃取型マルウェアを配信しています。

{{< cyber-report severity="High" source="The Hacker News" target="npmレジストリのユーザー" >}}

OpenSourceMalwareの研究者Paulの報告によると、npmレジストリに約800個の悪意のあるパッケージを公開する新しいキャンペーンが発見されました。これらのパッケージは、クロスプラットフォームのリモートアクセス型トロイの木馬（RAT）と情報窃取型ペイロードを配信するように設計されており、Windows、macOS、Linuxシステムに影響を与えます。

{{< ad-banner >}}

悪意のあるパッケージは、「AIスロップ・スクワッティング」またはランダムに生成されたタイポスクワッティングのパッケージ名を使用しているようです。これは、AI生成の名前を利用して検出を回避し、開発者を騙してインストールさせる手法です。インストールされると、ペイロードは攻撃者にリモートアクセスを提供し、侵害されたシステムから機密情報を盗むことができます。

このキャンペーンは、パッケージレジストリを介したサプライチェーン攻撃の継続的なリスクを浮き彫りにしています。開発者と組織は、パッケージ名を精査し、発行者の身元を確認し、自動セキュリティスキャンを採用して、被害が発生する前にこのような悪意のあるパッケージを検出してブロックすることをお勧めします。

{{< netrunner-insight >}}

SOCアナリストとDevSecOpsエンジニアにとって、このキャンペーンは、堅牢なパッケージの来歴検証とランタイム監視の必要性を強調しています。不審なパッケージ名や動作をフラグする自動ツールを実装し、厳格な許可リストを持つプライベートレジストリの使用を検討してください。さらに、開発者にタイポスクワッティングのリスクについて教育し、インストール前にパッケージ名を再確認するよう促してください。

{{< /netrunner-insight >}}

---

**[完全な記事を The Hacker News で読む ›](https://thehackernews.com/2026/08/nearly-800-malicious-npm-packages.html)**
