---
title: "Kimwolf v7 Android ボットネットがHTTP/2を使用してDDoS検出を回避"
date: "2026-08-16T07:27:33Z"
original_date: "2026-08-11T19:36:37"
lang: "ja"
translationKey: "kimwolf-v7-android-botnet-uses-http-2-to-evade-ddos-detection"
slug: "kimwolf-v7-android-botnet-uses-http-2-to-evade-ddos-detection"
author: "NewsBot (Validated by Federico Sella)"
description: "Unit 42によって発見された新しいKimwolf v7 AndroidおよびIoTボットネットは、HTTP/2を使用してDDoSトラフィックを正当なブラウジングのように見せかけ、回復力を向上させています。"
original_url: "https://thehackernews.com/2026/08/kimwolf-v7-android-botnet-makes-http2.html"
source: "The Hacker News"
severity: "Medium"
target: "AndroidおよびIoTデバイス"
cve: null
cvss: null
kev: null
tags: ["news", "cybersecurity"]
news-categories: ["cybersecurity"]
layout: "news"
draft: false
---

Unit 42によって発見された新しいKimwolf v7 AndroidおよびIoTボットネットは、HTTP/2を使用してDDoSトラフィックを正当なブラウジングのように見せかけ、回復力を向上させています。

{{< cyber-report severity="Medium" source="The Hacker News" target="AndroidおよびIoTデバイス" >}}

サイバーセキュリティ研究者らは、Kimwolf/AISURUボットネットの新バージョンであるKimwolf v7を発見しました。これはAndroidおよびモノのインターネット（IoT）デバイスを標的としています。この亜種は、Palo Alto Networks Unit 42によって2026年2月に特定され、運用上の回復力の向上と分散型サービス拒否（DDoS）攻撃の実行を目的とした大幅な強化が導入されています。

{{< ad-banner >}}

Kimwolf v7の主な改善点は、HTTP/2ベースのトラフィックの採用であり、これによりボットネットはDDoS攻撃トラフィックを正当なブラウジング活動のように見せかけることができます。この手法は、悪意のあるHTTP/2トラフィックと良性のHTTP/2トラフィックを効果的に区別できない可能性のあるセキュリティソリューションによる検出を回避するように設計されており、そのような攻撃の緩和をより困難にしています。

この発見は、ボットネット運営者が現代のセキュリティ防御を回避するためにツールを継続的に適応させている、その高度化の進化を浮き彫りにしています。ネットワーク内にAndroidおよびIoTデバイスを持つ組織は、この脅威を認識し、HTTP/2ベースの異常を考慮した検出メカニズムの更新を検討する必要があります。

{{< netrunner-insight >}}

SOCアナリストにとって、これは通常のHTTP/2トラフィックパターンをベースライン化し、トラフィックが正当に見える場合でも異常を検出できる行動分析を展開する必要性を強調しています。DevSecOpsチームは、DDoS緩和ソリューションがHTTP/2トラフィックを検査できることを確認し、アプリケーション層でのレート制限と異常検出を実装して、このような回避的な手法に対抗することを検討すべきです。

{{< /netrunner-insight >}}

---

**[完全な記事を The Hacker News で読む ›](https://thehackernews.com/2026/08/kimwolf-v7-android-botnet-makes-http2.html)**
