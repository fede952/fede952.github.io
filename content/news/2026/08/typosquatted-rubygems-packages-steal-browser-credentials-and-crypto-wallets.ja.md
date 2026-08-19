---
title: "タイポスクワッティングされたRubyGemsパッケージがブラウザの認証情報と暗号通貨ウォレットを窃取"
date: "2026-08-19T07:36:21Z"
original_date: "2026-08-18T11:20:00"
lang: "ja"
translationKey: "typosquatted-rubygems-packages-steal-browser-credentials-and-crypto-wallets"
slug: "typosquatted-rubygems-packages-steal-browser-credentials-and-crypto-wallets"
author: "NewsBot (Validated by Federico Sella)"
description: "研究者らは、Windowsベースの情報窃取型マルウェアを展開し、ブラウザの認証情報と暗号通貨ウォレットを標的とする、タイポスクワッティングされた16個のRubyGemsパッケージを報告している。"
original_url: "https://thehackernews.com/2026/08/16-typosquatted-rubygems-packages-steal.html"
source: "The Hacker News"
severity: "High"
target: "Windows上のRubyGemsユーザー"
cve: null
cvss: null
kev: null
tags: ["news", "cybersecurity"]
news-categories: ["cybersecurity"]
layout: "news"
draft: false
---

研究者らは、Windowsベースの情報窃取型マルウェアを展開し、ブラウザの認証情報と暗号通貨ウォレットを標的とする、タイポスクワッティングされた16個のRubyGemsパッケージを報告している。

{{< cyber-report severity="High" source="The Hacker News" target="Windows上のRubyGemsユーザー" >}}

サイバーセキュリティ研究者らは、RubyGemsユーザーを標的とし、Windowsベースの情報窃取型マルウェアを展開する新たなタイポスクワッティングキャンペーンを発見した。StubMakerとして追跡されるこのキャンペーンは、2026年8月15日にOpenSourceMalwareによって発見され、ブラウザの認証情報と暗号通貨ウォレットを窃取するように設計された16個の悪意のあるパッケージが含まれている。

{{< ad-banner >}}

悪意のあるパッケージには、'ubnuler'、'ubnlder'、'ri18nr'、'reaker'、'rakier'、'orakw'、'joxn'などの名前が含まれており、人気のあるgemのタイポスクワットである可能性が高く、開発者を騙してインストールさせます。インストールされると、この窃取型マルウェアはブラウザと暗号通貨ウォレット拡張機能から機密データを収集し、重大なサプライチェーンリスクをもたらします。

このキャンペーンは、オープンソースエコシステムにおけるタイポスクワッティングの継続的な脅威を浮き彫りにしています。開発者は、パッケージ名を慎重に確認し、信頼できるソースを使用し、プロジェクト内の不審な依存関係を監視することをお勧めします。

{{< netrunner-insight >}}

SOCアナリストにとって、このキャンペーンは、予期しないRubyGemsのインストールや不審なドメインへのネットワーク呼び出しを監視する必要性を強調しています。DevSecOpsエンジニアは、厳格な依存関係の固定を実施し、タイポスクワッティングされたパッケージをスキャンするツールを使用する必要があります。さらに、既知の悪意のあるパッケージ名をブロックし、開発者にタイポスクワッティングのリスクについて教育することを検討してください。

{{< /netrunner-insight >}}

---

**[完全な記事を The Hacker News で読む ›](https://thehackernews.com/2026/08/16-typosquatted-rubygems-packages-steal.html)**
