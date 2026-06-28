---
title: "FBI、ロシア諜報機関ハッカーがSignalのバックアップ復旧キーを標的に"
date: "2026-06-28T09:57:31Z"
original_date: "2026-06-26T19:38:29"
lang: "ja"
translationKey: "fbi-warns-russian-intel-hackers-target-signal-backup-recovery-keys"
author: "NewsBot (Validated by Federico Sella)"
description: "FBIとCISAが警告を更新：ロシア諜報機関のフィッシングがSignalのバックアップ復旧キーを盗み、プライベートメッセージを読み取り、アカウントを乗っ取る"
original_url: "https://thehackernews.com/2026/06/fbi-warns-russian-intelligence-hackers.html"
source: "The Hacker News"
severity: "High"
target: "Signalユーザー"
cve: null
cvss: null
kev: null
tags: ["news", "cybersecurity"]
news-categories: ["cybersecurity"]
layout: "news"
draft: false
---

FBIとCISAが警告を更新：ロシア諜報機関のフィッシングがSignalのバックアップ復旧キーを盗み、プライベートメッセージを読み取り、アカウントを乗っ取る

{{< cyber-report severity="High" source="The Hacker News" target="Signalユーザー" >}}

FBIとCISAは、Signalアカウントを標的としたロシア諜報機関のフィッシングキャンペーンに関する3月の警告を更新しました。攻撃者は新たな手順を追加し、標的を欺いてSignalのバックアップ復旧キーを渡させています。キーを入手すると、攻撃者はアカウントのバックアップを復元し、プライベートメッセージやグループメッセージの履歴を読み取り、アカウントを完全に乗っ取ることができます。

{{< ad-banner >}}

このキーは最初の侵害後も有効であり、持続的なアクセスを可能にします。この手法は従来の二要素認証を回避します。なぜなら、復旧キーは正当なアカウント復元のために設計されているからです。勧告では、ユーザーは復旧キーを決して共有せず、登録ロックやその他のセキュリティ機能を有効にするよう強調しています。

組織はユーザーにこの特定のフィッシングベクトルについて教育し、機密性の高い通信には追加の確認手順を実装することを検討すべきです。この脅威はロシア諜報機関によるものとされ、キャンペーンの地政学的背景を浮き彫りにしています。

{{< netrunner-insight >}}

これは、セキュリティ機能を標的としたソーシャルエンジニアリングの典型的な例です。SOCアナリストは、異常なアカウント復旧リクエストを監視し、Signalのバックアップ復旧キーは決して共有してはならないとユーザーに教育すべきです。DevSecOpsチームは、重要な通信に対してフィッシング耐性のある認証を統合することを検討すべきです。

{{< /netrunner-insight >}}

---

**[完全な記事を The Hacker News で読む ›](https://thehackernews.com/2026/06/fbi-warns-russian-intelligence-hackers.html)**
