---
title: "PostCSSツールを装った悪意のあるnpmパッケージがWindows RATを配信"
date: "2026-06-23T10:35:14Z"
original_date: "2026-06-23T08:54:32"
lang: "ja"
translationKey: "malicious-npm-packages-disguised-as-postcss-tools-deliver-windows-rat"
author: "NewsBot (Validated by Federico Sella)"
description: "PostCSSツールを装った3つの悪意のあるnpmパッケージが、Windowsリモートアクセス型トロイの木馬を配信していることが判明しました。研究者はnpmパッケージをインストールする際に注意を促しています。"
original_url: "https://thehackernews.com/2026/06/malicious-npm-packages-pose-as-postcss.html"
source: "The Hacker News"
severity: "High"
target: "npmユーザー、Windowsシステム"
cve: null
cvss: null
kev: null
tags: ["news", "cybersecurity"]
news-categories: ["cybersecurity"]
layout: "news"
draft: false
---

PostCSSツールを装った3つの悪意のあるnpmパッケージが、Windowsリモートアクセス型トロイの木馬を配信していることが判明しました。研究者はnpmパッケージをインストールする際に注意を促しています。

{{< cyber-report severity="High" source="The Hacker News" target="npmユーザー、Windowsシステム" >}}

サイバーセキュリティ研究者は、Windowsベースのリモートアクセス型トロイの木馬（RAT）を配信するように設計された3つの悪意のあるnpmパッケージ（aes-decode-runner-pro、postcss-minify-selector、postcss-minify-selector-parser）を特定しました。これらのパッケージは過去1ヶ月間にnpmユーザーによって公開され、合計1,016回のダウンロードを記録しており、中程度ながら懸念すべき拡散を示しています。

{{< ad-banner >}}

これらのパッケージは、人気のCSSポストプロセッサであるPostCSSの正当なツールを装い、開発者にインストールを促します。インストールされると、悪意のあるコードがペイロードを実行し、感染したWindowsマシンへのリモートアクセスを確立します。これにより、攻撃者はデータの窃取、追加のマルウェアのインストール、ネットワーク内での横断的な移動が可能になる可能性があります。

このインシデントは、npmエコシステムにおけるタイポスクワッティングや依存関係混乱の継続的な脅威を浮き彫りにしています。開発者はパッケージ名を注意深く確認し、インストール前にソースコードをレビューし、パッケージの整合性検証ツールを使用してリスクを軽減することを推奨します。

{{< netrunner-insight >}}

SOCアナリストやDevSecOpsエンジニアにとって、これは厳格なパッケージ出所確認を実施し、異常なnpmパッケージのインストールを監視するよう促す注意喚起です。既知の悪意のあるパッケージを自動的にスキャンし、開発者にパッケージ名を盲目的に信頼するリスクについて教育することを検討してください。ダウンロード数が比較的少ないことから、このキャンペーンは初期段階である可能性があり、同様のパッケージを積極的にハンティングすることが推奨されます。

{{< /netrunner-insight >}}

---

**[完全な記事を The Hacker News で読む ›](https://thehackernews.com/2026/06/malicious-npm-packages-pose-as-postcss.html)**
