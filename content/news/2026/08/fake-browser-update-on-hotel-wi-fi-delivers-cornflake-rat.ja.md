---
title: "ホテルのWi-Fiでの偽ブラウザ更新がCornFlake RATを配信"
date: "2026-08-01T09:04:02Z"
original_date: "2026-08-01T06:29:05"
lang: "ja"
translationKey: "fake-browser-update-on-hotel-wi-fi-delivers-cornflake-rat"
slug: "fake-browser-update-on-hotel-wi-fi-delivers-cornflake-rat"
author: "NewsBot (Validated by Federico Sella)"
description: "Microsoftは、乗っ取られたホテルのWi-Fiを利用して偽の更新を押し付け、CornFlake監視マルウェアを配信するCaptiveCrunch作戦について警告しています。"
original_url: "https://thehackernews.com/2026/08/hijacked-hotel-wi-fi-pushes-fake.html"
source: "The Hacker News"
severity: "High"
target: "ホテルのWi-Fi利用者"
cve: null
cvss: null
kev: null
tags: ["news", "cybersecurity"]
news-categories: ["cybersecurity"]
layout: "news"
draft: false
---

Microsoftは、乗っ取られたホテルのWi-Fiを利用して偽の更新を押し付け、CornFlake監視マルウェアを配信するCaptiveCrunch作戦について警告しています。

{{< cyber-report severity="High" source="The Hacker News" target="ホテルのWi-Fi利用者" >}}

Microsoftは、乗っ取られたホテルのWi-Fiネットワークを利用して偽のブラウザ更新を配信する、CaptiveCrunchとして追跡される新しいキャンペーンを公開しました。これらの更新は実際にはCornFlakeという名前のリモートアクセス型トロイの木馬（RAT）であり、ウェブカメラの画像、マイクの音声、キー入力をキャプチャし、感染したデバイスを事実上の監視ツールに変えることができます。

{{< ad-banner >}}

この作戦はStorm-2945によるものとされ、Microsoftはこれを既知の脅威グループMidnight Blizzardの運用サブクラスターと評価しています。これは、攻撃チェーンがホテルのネットワークインフラを侵害してユーザーのトラフィックを傍受し、悪意のある更新ページにリダイレクトすることを伴うため、高度な洗練度とリソースを示唆しています。

報告書は特定のCVEやCVSSスコアを指定していませんが、この攻撃ベクトルは、信頼できる環境（ホテルのWi-Fi）を利用してマルウェアを配信する点で注目に値します。旅行者やビジネスプロフェッショナルは、公共Wi-Fiに依存することが多く、ブラウザの更新プロンプトを精査せずに受け入れる可能性が高いため、特にリスクがあります。

{{< netrunner-insight >}}

このキャンペーンは、信頼できないネットワーク上のブラウザ更新プロンプトを疑ってかかることの重要性を強調しています。SOCアナリストは、最近ホテルや公共Wi-Fiに接続したエンドポイントからの異常なアウトバウンド接続を監視し、組織の許可リストにない更新関連ドメインをブロックまたはフラグすることを検討すべきです。DevSecOpsにとっては、厳格な更新ポリシーを施行し、リモートワーカーにエンタープライズグレードのVPNを使用することで、このようなウォーターホール型攻撃のリスクを軽減できます。

{{< /netrunner-insight >}}

---

**[完全な記事を The Hacker News で読む ›](https://thehackernews.com/2026/08/hijacked-hotel-wi-fi-pushes-fake.html)**
