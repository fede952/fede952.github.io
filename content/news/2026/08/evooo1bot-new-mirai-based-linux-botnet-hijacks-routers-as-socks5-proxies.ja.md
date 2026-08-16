---
title: "Evooo1Bot: Miraiベースの新しいLinuxボットネットがルーターをSOCKS5プロキシとして乗っ取る"
date: "2026-08-16T07:24:07Z"
original_date: "2026-08-15T14:14:38"
lang: "ja"
translationKey: "evooo1bot-new-mirai-based-linux-botnet-hijacks-routers-as-socks5-proxies"
slug: "evooo1bot-new-mirai-based-linux-botnet-hijacks-routers-as-socks5-proxies"
author: "NewsBot (Validated by Federico Sella)"
description: "Evooo1Botは、モジュール式のMirai亜種で、インターネットに面したゲートウェイを標的とし、ルーターをステルスなトラフィックのためのSOCKS5リレーノードに変えます。"
original_url: "https://www.bleepingcomputer.com/news/security/new-evooo1bot-linux-botnet-turns-routers-into-traffic-relay-nodes/"
source: "BleepingComputer"
severity: "High"
target: "インターネットに面したゲートウェイデバイス"
cve: null
cvss: null
kev: null
tags: ["news", "cybersecurity"]
news-categories: ["cybersecurity"]
layout: "news"
draft: false
---

Evooo1Botは、モジュール式のMirai亜種で、インターネットに面したゲートウェイを標的とし、ルーターをステルスなトラフィックのためのSOCKS5リレーノードに変えます。

{{< cyber-report severity="High" source="BleepingComputer" target="インターネットに面したゲートウェイデバイス" >}}

Evooo1Botという名前のMiraiベースの新しいLinuxボットネットが、ルーターやその他のネットワークアプライアンスなどのインターネットに面したゲートウェイデバイスを標的にしているのが観測されました。このマルウェアはモジュール式の設計で、初期侵害後に新しい機能で更新できるようになっています。

{{< ad-banner >}}

感染すると、侵害されたデバイスはSOCKS5トラフィックリレーノードとして再利用されます。これにより、ボットネットの運営者は、乗っ取られたルーターの分散ネットワークを通じて悪意のあるトラフィックをルーティングし、攻撃の発信元を隠し、ネットワークベースの防御を回避できる可能性があります。

SOCKS5リレーの使用は、典型的なMirai DDoS機能からの顕著な進化であり、ステルス性の高いプロキシベースの運用への移行を示しています。組織は、ゲートウェイデバイスにパッチを適用し、デフォルトの認証情報を変更し、リモート管理インターフェースをインターネットに公開しないようにする必要があります。

{{< netrunner-insight >}}

SOCアナリストにとって、これはネットワークデバイスからの異常なアウトバウンド接続を監視することの重要性を強調しています。SOCKS5リレーは悪意のあるトラフィックをトンネリングするために使用される可能性があるからです。DevSecOpsチームは、未使用のサービスを無効にし、強力な認証を強制し、管理インターフェースをセグメント化することで、ゲートウェイデバイスを強化すべきです。Mirai亜種は単純なDDoSツールを超えて進化し続けているため、プロアクティブな脅威ハンティングが不可欠です。

{{< /netrunner-insight >}}

---

**[完全な記事を BleepingComputer で読む ›](https://www.bleepingcomputer.com/news/security/new-evooo1bot-linux-botnet-turns-routers-into-traffic-relay-nodes/)**
