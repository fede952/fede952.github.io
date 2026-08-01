---
title: "HollowFrameローダーとMatryoshkaバックドアが法律事務所を標的に"
date: "2026-08-01T09:01:20Z"
original_date: "2026-07-31T16:39:31"
lang: "ja"
translationKey: "hollowframe-loader-and-matryoshka-backdoor-target-law-firm"
slug: "hollowframe-loader-and-matryoshka-backdoor-target-law-firm"
author: "NewsBot (Validated by Federico Sella)"
description: "Blackpoint Cyberによると、Goベースの新しいローダーHollowFrameとRustベースのMatryoshkaバックドアが、法律事務所を標的としたスピアフィッシング攻撃で使用された。"
original_url: "https://thehackernews.com/2026/07/hollowframe-loader-deploys-matryoshka.html"
source: "The Hacker News"
severity: "High"
target: "法律事務所"
cve: null
cvss: null
kev: null
tags: ["news", "cybersecurity"]
news-categories: ["cybersecurity"]
layout: "news"
draft: false
---

Blackpoint Cyberによると、Goベースの新しいローダーHollowFrameとRustベースのMatryoshkaバックドアが、法律事務所を標的としたスピアフィッシング攻撃で使用された。

{{< cyber-report severity="High" source="The Hacker News" target="法律事務所" >}}

Blackpoint Cyberは、法律事務所を標的とした新たな攻撃チェーンを発見した。この攻撃は、受信者に暗号化されたアーカイブをダウンロードさせるスピアフィッシングメールから始まる。アーカイブにはWindowsショートカット（LNK）ファイルが含まれており、実行されると多段階の感染プロセスが開始される。

{{< ad-banner >}}

この攻撃では、これまで文書化されていない2つのマルウェアファミリーが利用されている。GoベースのローダーフレームワークであるHollowFrameと、RustベースのバックドアであるMatryoshkaだ。ローダーはバックドアを配信する役割を担い、攻撃者に侵害されたシステムへのリモートアクセスを提供する。

このキャンペーンは、マルウェアツールの継続的な進化を浮き彫りにしている。攻撃者はGoやRustなどのクロスプラットフォーム言語を採用し、検出を回避し、分析を複雑化させている。スピアフィッシングでの暗号化アーカイブやLNKファイルの使用は一般的な戦術だが、これらの特定のツールの組み合わせは、新たな高度な層を追加している。

{{< netrunner-insight >}}

SOCアナリストは、LNKファイルの実行やメールリンクからのアーカイブダウンロードの監視を優先すべきである。これらはこの攻撃チェーンの初期の指標である。DevSecOpsチームは、暗号化アーカイブからのファイル実行をブロックまたはサンドボックス化することを検討し、エンドポイント検出および応答（EDR）ソリューションが、ローダー動作を示すGoおよびRustバイナリを検出するように調整されていることを確認する必要がある。

{{< /netrunner-insight >}}

---

**[完全な記事を The Hacker News で読む ›](https://thehackernews.com/2026/07/hollowframe-loader-deploys-matryoshka.html)**
