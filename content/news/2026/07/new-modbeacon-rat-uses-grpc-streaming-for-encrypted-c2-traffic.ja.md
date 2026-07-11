---
title: "新たなMODBEACON RAT、gRPCストリーミングで暗号化C2トラフィックを実現"
date: "2026-07-11T08:43:59Z"
original_date: "2026-07-10T13:15:23"
lang: "ja"
translationKey: "new-modbeacon-rat-uses-grpc-streaming-for-encrypted-c2-traffic"
slug: "new-modbeacon-rat-uses-grpc-streaming-for-encrypted-c2-traffic"
author: "NewsBot (Validated by Federico Sella)"
description: "中国にリンクするSilver FoxグループがSEOポイズニングを介してRustベースのMODBEACON RATを展開、gRPCストリーミングで暗号化C2通信を行う。"
original_url: "https://thehackernews.com/2026/07/new-modbeacon-rat-uses-grpc-streaming.html"
source: "The Hacker News"
severity: "High"
target: "偽インストーラ経由のWindowsユーザ"
cve: null
cvss: null
kev: null
tags: ["news", "cybersecurity"]
news-categories: ["cybersecurity"]
layout: "news"
draft: false
---

中国にリンクするSilver FoxグループがSEOポイズニングを介してRustベースのMODBEACON RATを展開、gRPCストリーミングで暗号化C2通信を行う。

{{< cyber-report severity="High" source="The Hacker News" target="偽インストーラ経由のWindowsユーザ" >}}

中国にリンクするサイバー犯罪グループSilver Foxが、MODBEACONと呼ばれる新たなRustベースのリモートアクセス型トロイの木馬（RAT）に関与しているとされる。このマルウェアはgRPCストリーミングを使用して暗号化されたC2トラフィックを送信し、検出を困難にしている。

{{< ad-banner >}}

中国のサイバーセキュリティ企業QiAnXinによると、Silver FoxはSEOポイズニング技術を用いた偽インストーラを介してMODBEACONを拡散している。同グループは低熟練度・高活動の運営に見えるかもしれないが、実際の組織能力はより高度である。

C2通信へのgRPCストリーミングの使用はマルウェアにとって新しい手法であり、HTTP/2とプロトコルバッファを活用して正規のトラフィックに紛れ込む。セキュリティチームは異常なgRPCトラフィックを監視し、SEOポイズニングされたダウンロードサイトを調査すべきである。

{{< netrunner-insight >}}

SOCアナリストは検出パイプラインにgRPCトラフィック分析を追加すべきである。MODBEACONのストリーミングRPC使用は従来のネットワークシグネチャを回避できる。DevSecOpsチームはソフトウェアダウンロードの整合性を検証し、既知のSEOポイズニングドメインをブロックすることを検討すべきである。このRATはRustベースのマルウェアに対するプロアクティブな脅威ハンティングの必要性を強調している。

{{< /netrunner-insight >}}

---

**[完全な記事を The Hacker News で読む ›](https://thehackernews.com/2026/07/new-modbeacon-rat-uses-grpc-streaming.html)**
