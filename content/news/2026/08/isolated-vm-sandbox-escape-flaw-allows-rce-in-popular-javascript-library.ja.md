---
title: "isolated-vm サンドボックスエスケープの脆弱性により、人気のJavaScriptライブラリでRCEが可能に"
date: "2026-08-21T07:37:09Z"
original_date: "2026-08-20T13:48:24"
lang: "ja"
translationKey: "isolated-vm-sandbox-escape-flaw-allows-rce-in-popular-javascript-library"
slug: "isolated-vm-sandbox-escape-flaw-allows-rce-in-popular-javascript-library"
author: "NewsBot (Validated by Federico Sella)"
description: "isolated-vm の重大な脆弱性により、サンドボックス化されたJavaScriptがホストにエスケープし、リモートコード実行が可能になる可能性があります。バージョン7.0.0までのすべてのバージョンが影響を受けます。"
original_url: "https://thehackernews.com/2026/08/isolated-vm-flaw-lets-sandboxed.html"
source: "The Hacker News"
severity: "Critical"
target: "isolated-vm JavaScriptサンドボックスライブラリ"
cve: null
cvss: null
kev: null
tags: ["news", "cybersecurity"]
news-categories: ["cybersecurity"]
layout: "news"
draft: false
---

isolated-vm の重大な脆弱性により、サンドボックス化されたJavaScriptがホストにエスケープし、リモートコード実行が可能になる可能性があります。バージョン7.0.0までのすべてのバージョンが影響を受けます。

{{< cyber-report severity="Critical" source="The Hacker News" target="isolated-vm JavaScriptサンドボックスライブラリ" >}}

広く使用されているオープンソースのJavaScriptサンドボックスライブラリであるisolated-vm（GitHubで2,900以上のスターと190のフォークを持つ）に、重大なセキュリティ脆弱性が開示されました。GHSA-864f-rcv7-6rh4として追跡されるこの脆弱性により、攻撃者はサンドボックス環境をエスケープし、ホストシステム上で任意のコードを実行できる可能性があります。ライブラリのバージョン7.0.0までのすべてのバージョンが影響を受けます。

{{< ad-banner >}}

この脆弱性は、isolated-vmが信頼できないJavaScriptコードを実行するための安全な境界を提供するように設計されているため、特に懸念されます。サンドボックスエスケープが成功すると、ホストアプリケーションと基盤となるインフラストラクチャが危険にさらされる可能性があります。CVE識別子はまだ割り当てられていませんが、このアドバイザリは、このライブラリを使用する開発者による即時の対応の必要性を強調しています。

isolated-vmに依存している組織は、パッチを監視し、信頼できないコードの実行を制限する、または追加の分離レイヤーを適用するなどの緩和策を検討する必要があります。現時点でCVEがないことは深刻度を軽減するものではなく、概念実証エクスプロイトがセキュリティコミュニティですでに流通している可能性があります。

{{< netrunner-insight >}}

このサンドボックスエスケープは、専用の分離ツールでさえ重大な欠陥を持つ可能性があることをはっきりと示しています。SOCアナリストは、isolated-vmを使用するアプリケーションをインベントリし、修正が利用可能になったらパッチ適用を優先する必要があります。DevSecOpsチームは、サンドボックス戦略をレビューし、サンドボックスを別のコンテナやVMで実行して爆発半径を制限するなど、多層防御を検討する必要があります。

{{< /netrunner-insight >}}

---

**[完全な記事を The Hacker News で読む ›](https://thehackernews.com/2026/08/isolated-vm-flaw-lets-sandboxed.html)**
