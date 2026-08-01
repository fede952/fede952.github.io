---
title: "中国のハッカーがTelegram経由でDeepSeekを使用し自律攻撃を開始"
date: "2026-08-01T09:07:32Z"
original_date: "2026-07-31T11:21:27"
lang: "ja"
translationKey: "chinese-hacker-uses-deepseek-via-telegram-to-launch-autonomous-attacks"
slug: "chinese-hacker-uses-deepseek-via-telegram-to-launch-autonomous-attacks"
author: "NewsBot (Validated by Federico Sella)"
description: "Unit 42は、中国語を話す脅威アクターがHermes Agentを通じてDeepSeekを活用し、単一のTelegramコマンド後にインターネットに面したシステムを自律的に攻撃することを報告しています。"
original_url: "https://thehackernews.com/2026/07/chinese-hacker-commands-deepseek-via.html"
source: "The Hacker News"
severity: "High"
target: "インターネットに面したシステム"
cve: null
cvss: null
kev: null
tags: ["news", "cybersecurity"]
news-categories: ["cybersecurity"]
layout: "news"
draft: false
---

Unit 42は、中国語を話す脅威アクターがHermes Agentを通じてDeepSeekを活用し、単一のTelegramコマンド後にインターネットに面したシステムを自律的に攻撃することを報告しています。

{{< cyber-report severity="High" source="The Hacker News" target="インターネットに面したシステム" >}}

Palo Alto NetworksのUnit 42は、中国語を話す脅威アクター（knaitheおよびKnYuanという別名で追跡）が、オープンソースのHermes Agentフレームワークを通じてDeepSeek AIモデルを使用し、自律攻撃を実施する新たな攻撃チェーンを公開しました。この操作は単一のTelegram命令で始まり、その後エージェントは独立してインターネットに面したシステムを特定し、適切な公開エクスプロイトを選択しました。

{{< ad-banner >}}

研究者によると、セッション中にそれ以上のオペレーター入力は回収されておらず、高度な自動化を示しています。これは、AIエージェントが継続的な人間の指示なしに偵察、エクスプロイト選択、実行を処理する、AI支援型サイバー攻撃の重要な進化を示しています。

この調査結果は、AI駆動型の自律攻撃ツールの脅威が増大していることを浮き彫りにしており、これによりスキルの低い攻撃者への障壁が低下し、操作の速度と規模が増大します。組織は、マシンスピードで動作し環境に適応できるこのような自動化された脅威に対抗するために、防御を適応させる必要があります。

{{< netrunner-insight >}}

このインシデントは、SOCがAI駆動型の攻撃パターン（典型的な人為的エラーの兆候を欠く可能性のある、迅速で自動化されたエクスプロイト試行など）を監視する緊急の必要性を強調しています。DevSecOpsチームは、インターネットに面した資産の強化と、自律的な脅威に対抗するための自動検出および対応メカニズムの実装を優先すべきです。さらに、AIモデルへのアクセスを制限し、AI支援攻撃を示す可能性のある異常なAPI使用を監視することを検討してください。

{{< /netrunner-insight >}}

---

**[完全な記事を The Hacker News で読む ›](https://thehackernews.com/2026/07/chinese-hacker-commands-deepseek-via.html)**
