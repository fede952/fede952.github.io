---
title: "TrojPix攻撃、ビデオケーブルの放射を利用してエアギャップシステムからデータを窃取"
date: "2026-07-06T11:24:53Z"
original_date: "2026-07-06T08:50:54"
lang: "ja"
translationKey: "trojpix-attack-exfiltrates-data-from-air-gapped-systems-via-video-cable-emissions"
slug: "trojpix-attack-exfiltrates-data-from-air-gapped-systems-via-video-cable-emissions"
author: "NewsBot (Validated by Federico Sella)"
description: "研究者らがTrojPixを実証。これは、画面上のピクセルを変調してビデオケーブルから微弱な無線信号を放射させることで、エアギャップコンピュータからデータを漏洩させる手法であり、事前のマルウェアアクセスが必要。"
original_url: "https://thehackernews.com/2026/07/new-trojpix-attack-leaks-data-from-air.html"
source: "The Hacker News"
severity: "Medium"
target: "エアギャップシステム"
cve: null
cvss: null
kev: null
tags: ["news", "cybersecurity"]
news-categories: ["cybersecurity"]
layout: "news"
draft: false
---

研究者らがTrojPixを実証。これは、画面上のピクセルを変調してビデオケーブルから微弱な無線信号を放射させることで、エアギャップコンピュータからデータを漏洩させる手法であり、事前のマルウェアアクセスが必要。

{{< cyber-report severity="Medium" source="The Hacker News" target="エアギャップシステム" >}}

山東大学の研究者らは、TrojPixと呼ばれる新たな攻撃手法を発表した。これは、ビデオケーブルからの電磁放射を悪用して、エアギャップコンピュータからデータを窃取するものである。この手法は、人間の目には知覚できない方法で画面上のピクセルを微妙に変化させ、ビデオケーブルから微弱な無線信号を放射させ、近くの受信機で捕捉・復号できるようにする。

{{< ad-banner >}}

TrojPixは、標的システムに事前にマルウェアをインストールしてピクセル値を操作する必要がある。このアプローチは、従来のエアギャップ隠蔽チャネルと比較して大幅に高いデータ転送速度を達成し、高度にセキュアな環境において現実的な脅威となる。この攻撃は、物理的に隔離されたネットワークであってもデータを保護することの継続的な課題を浮き彫りにしている。

この手法は高度ではあるが、既存のマルウェアに依存するため、その適用範囲は限られる。組織は、堅牢なエンドポイントセキュリティと機密エリアでの異常な電磁放射の監視を通じて、初期侵害の防止に注力すべきである。

{{< netrunner-insight >}}

SOCアナリストにとって、TrojPixはエアギャップシステムがデータ漏洩に対して無防備ではないことを強調している。機密性の高いワークステーションの近くで異常な電磁信号を監視し、厳格な物理的セキュリティを実施すること。DevSecOpsチームは、ビデオケーブルのシールドや、可能な場合はピクセルレベルの異常検知の実装を検討すべきである。

{{< /netrunner-insight >}}

---

**[完全な記事を The Hacker News で読む ›](https://thehackernews.com/2026/07/new-trojpix-attack-leaks-data-from-air.html)**
