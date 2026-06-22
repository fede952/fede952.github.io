---
title: "AryStingerボットネットが4,000台以上のD-Linkルーターを乗っ取り、プロキシトラフィックに悪用"
date: "2026-06-22T12:48:45Z"
original_date: "2026-06-21T14:14:22"
lang: "ja"
translationKey: "arystinger-botnet-hijacks-4000-d-link-routers-for-proxy-traffic"
author: "NewsBot (Validated by Federico Sella)"
description: "AryStingerと名付けられた新しいボットネットが、4,000台以上の古いD-Linkルーターを侵害し、悪意のあるトラフィックのプロキシとして利用しています。CVEやCVSSのデータはありません。"
original_url: "https://www.bleepingcomputer.com/news/security/arystinger-botnet-infected-thousands-of-d-link-routers-worldwide/"
source: "BleepingComputer"
severity: "Medium"
target: "古いD-Linkルーター"
cve: null
cvss: null
kev: null
tags: ["news", "cybersecurity"]
news-categories: ["cybersecurity"]
layout: "news"
draft: false
---

AryStingerと名付けられた新しいボットネットが、4,000台以上の古いD-Linkルーターを侵害し、悪意のあるトラフィックのプロキシとして利用しています。CVEやCVSSのデータはありません。

{{< cyber-report severity="Medium" source="BleepingComputer" target="古いD-Linkルーター" >}}

BleepingComputerの報告によると、これまで文書化されていなかったAryStingerというマルウェアボットネットが、世界中の4,000台以上の古いD-Linkルーターを侵害しました。このボットネットはこれらのデバイスを悪意のあるトラフィックのプロキシとして利用し、攻撃者が活動を匿名化し、さらなる攻撃を仕掛けることを可能にしています。

{{< ad-banner >}}

侵害されたルーターは、既知の脆弱性を持つ古いファームウェアを実行していると考えられていますが、報告書では特定のCVE識別子は開示されていません。ボットネットのインフラと伝播方法は分析中ですが、感染規模はパッチ未適用のIoTデバイスがもたらすリスクを浮き彫りにしています。

組織はネットワークデバイスの棚卸し、ファームウェアの最新化、プロキシ使用を示す異常なトラフィックパターンの監視を推奨します。初期報告書に詳細な技術的指標が不足していることから、検出シグネチャを開発するにはさらなる調査が必要です。

{{< netrunner-insight >}}

SOCアナリストにとって、これはネットワークデバイス、特に古いルーターからの予期しない発信接続を監視するよう促す注意喚起です。DevSecOpsチームはファームウェア更新ポリシーを徹底し、IoTデバイスを重要なネットワークから分離することを検討すべきです。具体的なIoCがない場合、ベースライントラフィック分析とデバイスフィンガープリンティングが、このようなボットネット活動を発見する鍵となります。

{{< /netrunner-insight >}}

---

**[完全な記事を BleepingComputer で読む ›](https://www.bleepingcomputer.com/news/security/arystinger-botnet-infected-thousands-of-d-link-routers-worldwide/)**
