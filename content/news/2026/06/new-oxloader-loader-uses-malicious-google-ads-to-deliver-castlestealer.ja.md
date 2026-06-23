---
title: "新たなOXLOADERローダー、悪意あるGoogle広告でCastleStealerを配布"
date: "2026-06-23T10:32:59Z"
original_date: "2026-06-22T13:20:12"
lang: "ja"
translationKey: "new-oxloader-loader-uses-malicious-google-ads-to-deliver-castlestealer"
author: "NewsBot (Validated by Federico Sella)"
description: "Elastic Security Labsが、悪意あるGoogle広告を利用してOXLOADERローダーを配布し、CastleStealerマルウェアを届けるキャンペーンを公開。ロシア語圏の脅威アクターが関与している可能性が高い。"
original_url: "https://thehackernews.com/2026/06/new-oxloader-loader-uses-malicious.html"
source: "The Hacker News"
severity: "High"
target: "悪意あるGoogle広告をクリックしたユーザー"
cve: null
cvss: null
kev: null
tags: ["news", "cybersecurity"]
news-categories: ["cybersecurity"]
layout: "news"
draft: false
---

Elastic Security Labsが、悪意あるGoogle広告を利用してOXLOADERローダーを配布し、CastleStealerマルウェアを届けるキャンペーンを公開。ロシア語圏の脅威アクターが関与している可能性が高い。

{{< cyber-report severity="High" source="The Hacker News" target="悪意あるGoogle広告をクリックしたユーザー" >}}

Elastic Security Labsのサイバーセキュリティ研究者らは、悪意あるGoogle広告を利用して、これまで報告されていなかったOXLOADERというマルウェアローダーを配布する新たなキャンペーンを発見した。このローダーは、認証情報を盗むマルウェアCastleStealerを無防備な被害者に届けるために使用される。

{{< ad-banner >}}

このキャンペーンは金銭目的であり、ロシア語圏の脅威アクターによって運営されている可能性が高い。初期感染経路としてGoogle広告を利用することで、サイバー犯罪者は従来のセキュリティ対策を回避し、より広い範囲のユーザーにリーチする戦術を進化させている。

組織や個人は、一見正当なソースからの広告であっても、クリックする際には注意を払うことが推奨される。広告ブロッカーの導入や最新のセキュリティソフトウェアの維持は、このような攻撃のリスクを軽減するのに役立つ。

{{< netrunner-insight >}}

SOCアナリストにとって、異常な広告クリックやその後の未知のドメインへのネットワーク接続を監視することが重要です。DevSecOpsチームは、プロキシフィルターで広告関連ドメインをブロックし、信頼できる検索エンジンからの広告であってもクリックするリスクについてユーザーを教育することを検討すべきです。

{{< /netrunner-insight >}}

---

**[完全な記事を The Hacker News で読む ›](https://thehackernews.com/2026/06/new-oxloader-loader-uses-malicious.html)**
