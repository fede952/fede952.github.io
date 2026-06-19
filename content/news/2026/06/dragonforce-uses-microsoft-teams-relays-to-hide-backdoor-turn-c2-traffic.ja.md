---
title: "DragonForce、Microsoft Teamsリレーを悪用してバックドア「Backdoor.Turn」のC2トラフィックを隠蔽"
date: "2026-06-19T11:15:07Z"
original_date: "2026-06-18T13:30:07"
lang: "ja"
translationKey: "dragonforce-uses-microsoft-teams-relays-to-hide-backdoor-turn-c2-traffic"
author: "NewsBot (Validated by Federico Sella)"
description: "DragonForceランサムウェアグループがカスタムGoベースのRAT「Backdoor.Turn」を展開し、Microsoft Teamsリレー内にC2トラフィックを隠蔽。米国の大手サービス企業を標的に。"
original_url: "https://thehackernews.com/2026/06/dragonforce-hackers-abuse-microsoft.html"
source: "The Hacker News"
severity: "High"
target: "米国の大手サービス企業"
cve: null
cvss: null
kev: null
tags: ["news", "cybersecurity"]
news-categories: ["cybersecurity"]
layout: "news"
draft: false
---

DragonForceランサムウェアグループがカスタムGoベースのRAT「Backdoor.Turn」を展開し、Microsoft Teamsリレー内にC2トラフィックを隠蔽。米国の大手サービス企業を標的に。

{{< cyber-report severity="High" source="The Hacker News" target="米国の大手サービス企業" >}}

DragonForceランサムウェアグループに関連する脅威アクターが、カスタムGoベースのリモートアクセス型トロイの木馬（RAT）「Backdoor.Turn」を使用し、Microsoft Teamsリレーインフラ内にC2トラフィックを隠蔽していることが確認された。Broadcom傘下のSymantecおよびCarbon Blackの調査結果によると、このバックドアは米国の大手サービス企業に対して展開された。

{{< ad-banner >}}

正規のMicrosoft Teamsリレーを悪用することで、攻撃者は悪意のあるトラフィックを通常のビジネス通信に紛れ込ませ、ネットワーク防御側の検出を困難にしている。GoベースのRATは、攻撃者に持続的なアクセスと、コマンド実行、データ窃取、追加ペイロード展開の能力を提供する。

この手法は、従来のネットワーク監視ツールを回避するためのランサムウェアグループの進化する戦術を浮き彫りにしている。Microsoft Teamsを利用する組織は、セキュリティ設定を見直し、異常なリレートラフィックパターンを監視すべきである。

{{< netrunner-insight >}}

SOCアナリストは、特に非標準のエンドポイントや時間外における異常なMicrosoft Teamsリレートラフィックを監視すべきである。DevSecOpsチームは、厳格なアプリケーション許可リストを適用し、C2通信を示す可能性のある暗号化トンネルがないかTeamsトラフィックを検査する必要がある。この攻撃は、信頼されたコラボレーションプラットフォームであってもゼロトラストの原則が必要であることを示している。

{{< /netrunner-insight >}}

---

**[完全な記事を The Hacker News で読む ›](https://thehackernews.com/2026/06/dragonforce-hackers-abuse-microsoft.html)**
