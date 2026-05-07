---
title: "Mirai派生のxlabs_v1ボットネットがADB経由でIoTデバイスを乗っ取り、DDoS攻撃を展開"
date: "2026-05-07T09:27:29Z"
original_date: "2026-05-06T20:21:00"
lang: "ja"
translationKey: "mirai-derived-xlabs-v1-botnet-hijacks-iot-devices-via-adb-for-ddos"
author: "NewsBot (Validated by Federico Sella)"
description: "研究者らが、露出したAndroid Debug Bridgeポートを悪用してIoTデバイスをDDoSネットワークに勧誘する、Miraiベースの新しいボットネット「xlabs_v1」を発見。"
original_url: "https://thehackernews.com/2026/05/mirai-based-xlabsv1-botnet-exploits-adb.html"
source: "The Hacker News"
severity: "High"
target: "ADBが露出したIoTデバイス"
cve: null
cvss: null
kev: null
tags: ["news", "cybersecurity"]
news-categories: ["cybersecurity"]
layout: "news"
draft: false
---

研究者らが、露出したAndroid Debug Bridgeポートを悪用してIoTデバイスをDDoSネットワークに勧誘する、Miraiベースの新しいボットネット「xlabs_v1」を発見。

{{< cyber-report severity="High" source="The Hacker News" target="ADBが露出したIoTデバイス" >}}

サイバーセキュリティ研究者らは、Android Debug Bridge（ADB）を実行するインターネットに露出したデバイスを標的とする、Mirai派生の新しいボットネット（自称xlabs_v1）を特定した。このボットネットは、侵害したデバイスを分散型サービス拒否（DDoS）攻撃を仕掛けられるネットワークに組み込むことを目的としている。

{{< ad-banner >}}

この発見は、Hunt.ioがオランダにホストされたサーバー上の露出したディレクトリを特定した後になされた。マルウェアは、Androidデバイスのデバッグに使用されるコマンドラインツールであるADBを悪用する。ADBはIoTデバイスで露出したまま放置されることが多く、リモートの攻撃者が不正アクセスを得ることを可能にする。

このキャンペーンは、セキュリティが不十分なIoTデバイスを標的とするMirai亜種の継続的な脅威を浮き彫りにしている。組織は、本番デバイスでADBを無効にし、ネットワークアクセスを制限して、このような乗っ取りを防ぐことが推奨される。

{{< netrunner-insight >}}

SOCアナリストは、外部IPからの予期しないADB接続を監視すべきです。DevSecOpsチームは、本番ビルドでADBが無効化されていること、およびIoTデバイスが重要なネットワークからセグメント化されていることを確認し、このボットネットのリーチを軽減してください。

{{< /netrunner-insight >}}

---

**[完全な記事を The Hacker News で読む ›](https://thehackernews.com/2026/05/mirai-based-xlabsv1-botnet-exploits-adb.html)**
