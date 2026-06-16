---
title: "DragonForceランサムウェア、Microsoft Teamsリレーを悪用してC2トラフィックを隠蔽"
date: "2026-06-16T12:10:12Z"
original_date: "2026-06-16T10:18:48"
lang: "ja"
translationKey: "dragonforce-ransomware-uses-microsoft-teams-relays-to-hide-c2-traffic"
author: "NewsBot (Validated by Federico Sella)"
description: "DragonForceランサムウェアは、カスタムマルウェア「Backdoor.Turn」を展開し、Microsoft Teamsリレーインフラ内でコマンド＆コントロールトラフィックを隠蔽します。"
original_url: "https://www.bleepingcomputer.com/news/security/ransomware-gang-abuses-microsoft-teams-relays-to-hide-malicious-traffic/"
source: "BleepingComputer"
severity: "High"
target: "Microsoft Teamsリレーインフラ"
cve: null
cvss: null
kev: null
tags: ["news", "cybersecurity"]
news-categories: ["cybersecurity"]
layout: "news"
draft: false
---

DragonForceランサムウェアは、カスタムマルウェア「Backdoor.Turn」を展開し、Microsoft Teamsリレーインフラ内でコマンド＆コントロールトラフィックを隠蔽します。

{{< cyber-report severity="High" source="BleepingComputer" target="Microsoft Teamsリレーインフラ" >}}

DragonForceランサムウェアグループは、カスタムマルウェア「Backdoor.Turn」を使用して、Microsoft Teamsリレーインフラ内でコマンド＆コントロール（C2）トラフィックを隠蔽していることが確認されました。この手法により、攻撃者は悪意のある通信を正当なTeamsトラフィックに紛れ込ませ、ネットワーク防御側の検出を困難にします。

{{< ad-banner >}}

Microsoft Teamsリレーを悪用することで、ランサムウェアグループは、信頼できるサービスへのトラフィックを精査しない可能性のある従来のネットワークセキュリティ制御を回避できます。このマルウェアは、TeamsのAPIやプロトコルを利用してC2データをトンネリングし、シグネチャベースの検出を回避し、侵害されたネットワークへの永続的なアクセスを可能にしていると考えられます。

Microsoft Teamsを利用する組織は、Teamsエンドポイントへの異常なアウトバウンドトラフィックパターンを監視し、暗号化トンネルの追加検査を検討する必要があります。このインシデントは、ランサムウェアグループが検出を回避するために、Living-off-the-Landや信頼できるサービスの悪用といった手法を採用する傾向が高まっていることを浮き彫りにしています。

{{< netrunner-insight >}}

SOCアナリストにとって、これは通常のTeamsトラフィックのベースラインを確立し、予期しないデータ量や非標準のTeamsエンドポイントへの接続などの異常を警告する必要性を強調しています。DevSecOpsチームは、Teamsの統合権限をレビューし、不要なAPIアクセスを制限して、リレー悪用の攻撃対象領域を減らすべきです。

{{< /netrunner-insight >}}

---

**[完全な記事を BleepingComputer で読む ›](https://www.bleepingcomputer.com/news/security/ransomware-gang-abuses-microsoft-teams-relays-to-hide-malicious-traffic/)**
