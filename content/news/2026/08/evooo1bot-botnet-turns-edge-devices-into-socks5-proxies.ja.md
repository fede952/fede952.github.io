---
title: "Evooo1BotボットネットがエッジデバイスをSOCKS5プロキシに変える"
date: "2026-08-18T07:31:16Z"
original_date: "2026-08-17T09:29:55"
lang: "ja"
translationKey: "evooo1bot-botnet-turns-edge-devices-into-socks5-proxies"
slug: "evooo1bot-botnet-turns-edge-devices-into-socks5-proxies"
author: "NewsBot (Validated by Federico Sella)"
description: "Miraiから派生した新しいLinuxボットネットEvooo1Botは、既知の脆弱性を悪用してエッジデバイスをSOCKS5プロキシに変え、ステルス攻撃を行います。"
original_url: "https://thehackernews.com/2026/08/evooo1bot-linux-botnet-exploits-known.html"
source: "The Hacker News"
severity: "High"
target: "インターネットに面したエッジデバイス"
cve: null
cvss: null
kev: null
tags: ["news", "cybersecurity"]
news-categories: ["cybersecurity"]
layout: "news"
draft: false
---

Miraiから派生した新しいLinuxボットネットEvooo1Botは、既知の脆弱性を悪用してエッジデバイスをSOCKS5プロキシに変え、ステルス攻撃を行います。

{{< cyber-report severity="High" source="The Hacker News" target="インターネットに面したエッジデバイス" >}}

サイバーセキュリティ研究者は、公開されたMiraiボットネットのソースコードから中核機能を派生させた、これまで文書化されていなかったLinuxボットネットファミリー「Evooo1Bot」を特定しました。このマルウェアは、インターネットに面したデバイスをSOCKS5プロキシに変え、攻撃者が侵害されたデバイスを介して悪意のあるトラフィックをルーティングできるように設計されています。

{{< ad-banner >}}

Evooo1BotはMiraiのDDoSエンジンを再利用していますが、エッジデバイスの既知の脆弱性を悪用する機能など、元のフレームワークを拡張した追加機能を備えています。これにより、ボットネットはリーチを拡大し、侵害されたシステム上で持続性を維持できます。

この発見は、Miraiベースのボットネットの継続的な進化を浮き彫りにしています。これらのボットネットは、脆弱なIoTおよびエッジデバイスを大規模なプロキシネットワークに勧誘する能力があるため、依然として重大な脅威です。組織は、既知の脆弱性にパッチを適用し、異常なプロキシトラフィックを監視することをお勧めします。

{{< netrunner-insight >}}

SOCアナリストにとって、このボットネットは、送信プロキシトラフィックの監視と異常なSOCKS5接続の検出の重要性を強調しています。DevSecOpsチームは、エッジデバイスの既知の脆弱性にパッチを適用することを優先し、ネットワークセグメンテーションを検討して、このようなボットネットの影響を制限する必要があります。Miraiコードの再利用により、既存の検出シグネチャはこの新しい亜種を検出するために更新が必要になる場合があります。

{{< /netrunner-insight >}}

---

**[完全な記事を The Hacker News で読む ›](https://thehackernews.com/2026/08/evooo1bot-linux-botnet-exploits-known.html)**
