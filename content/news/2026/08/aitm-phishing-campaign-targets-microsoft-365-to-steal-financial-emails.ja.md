---
title: "AitMフィッシングキャンペーンがMicrosoft 365を標的にし、財務関連メールを窃取"
date: "2026-08-08T07:47:42Z"
original_date: "2026-08-07T10:38:27"
lang: "ja"
translationKey: "aitm-phishing-campaign-targets-microsoft-365-to-steal-financial-emails"
slug: "aitm-phishing-campaign-targets-microsoft-365-to-steal-financial-emails"
author: "NewsBot (Validated by Federico Sella)"
description: "広範なメール駆動型フィッシングが中間者攻撃を利用してMicrosoft 365アカウントを乗っ取り、給与や財務関連のメール収集を狙っています。"
original_url: "https://thehackernews.com/2026/08/microsoft-365-aitm-phishing-hijacks.html"
source: "The Hacker News"
severity: "High"
target: "Microsoft 365アカウント"
cve: null
cvss: null
kev: null
tags: ["news", "cybersecurity"]
news-categories: ["cybersecurity"]
layout: "news"
draft: false
---

広範なメール駆動型フィッシングが中間者攻撃を利用してMicrosoft 365アカウントを乗っ取り、給与や財務関連のメール収集を狙っています。

{{< cyber-report severity="High" source="The Hacker News" target="Microsoft 365アカウント" >}}

サイバーセキュリティ研究者は、中間者攻撃（AitM）技術を利用してMicrosoft 365アカウントを侵害する、活発で広範なメール駆動型フィッシングキャンペーンを特定しました。このキャンペーンの主な目的は、財務ワークフローに関与する主要な担当者を特定し、関連するメール通信、特に給与や財務に関するものを外部に持ち出すことです。

{{< ad-banner >}}

攻撃者は住宅用プロキシを利用して、悪意のあるサインインを通常の消費者トラフィックに見せかけ、疑わしいIPアドレスをフラグ付けするセキュリティ制御による検出を回避します。この技術により、攻撃者は侵害したアカウントへのアクセスを維持し、即座に警告を発することなくアクセスし続けることができます。

Microsoft 365を使用する組織は、このようなAitMフィッシングの試みに対して警戒すべきです。これらの攻撃は、認証情報とセッショントークンをリアルタイムで中継することにより、多要素認証をしばしば迂回します。このキャンペーンが財務データに焦点を当てていることは、金融詐欺やビジネスメール詐欺（BEC）を促進するための標的型の取り組みを示唆しています。

{{< netrunner-insight >}}

このキャンペーンは、FIDO2セキュリティキーなどのフィッシング耐性のあるMFAと、特に住宅用IPレンジからの異常なサインインを継続的に監視する必要性を強調しています。SOCチームはまた、AitMツールキットの検出ルールを優先し、リスクシグナルに基づいてアクセスを制限する条件付きアクセスポリシーを適用する必要があります。DevSecOpsエンジニアは、トークンリレー攻撃を緩和するために、セッションバインディングとデバイスコンプライアンスチェックの実装を検討すべきです。

{{< /netrunner-insight >}}

---

**[完全な記事を The Hacker News で読む ›](https://thehackernews.com/2026/08/microsoft-365-aitm-phishing-hijacks.html)**
