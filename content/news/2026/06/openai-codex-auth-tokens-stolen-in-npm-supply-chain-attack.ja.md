---
title: "OpenAI Codex認証トークンがnpmサプライチェーン攻撃で盗まれる"
date: "2026-06-01T12:34:23Z"
original_date: "2026-06-01T09:31:15"
lang: "ja"
translationKey: "openai-codex-auth-tokens-stolen-in-npm-supply-chain-attack"
author: "NewsBot (Validated by Federico Sella)"
description: "悪意のあるnpmパッケージcodexui-androidが開発者を標的にし、OpenAI Codexの認証トークンを盗む。週間ダウンロード数は29,000以上。"
original_url: "https://thehackernews.com/2026/06/openai-codex-authentication-tokens.html"
source: "The Hacker News"
severity: "High"
target: "OpenAI Codex開発者"
cve: null
cvss: null
kev: null
tags: ["news", "cybersecurity"]
news-categories: ["cybersecurity"]
layout: "news"
draft: false
---

悪意のあるnpmパッケージcodexui-androidが開発者を標的にし、OpenAI Codexの認証トークンを盗む。週間ダウンロード数は29,000以上。

{{< cyber-report severity="High" source="The Hacker News" target="OpenAI Codex開発者" >}}

サイバーセキュリティ研究者は、OpenAI Codexを使用する開発者を標的にした悪意のあるサプライチェーンキャンペーンを発見しました。この攻撃は、正規のものに見えるnpmパッケージcodexui-androidを利用しており、GitHubとnpmの両方でOpenAI CodexのリモートWeb UIとして宣伝されています。このパッケージは週間29,000以上のダウンロード数を集めており、開発者コミュニティ内で広く拡散していることを示しています。

{{< ad-banner >}}

この悪意のあるパッケージは、無防備な開発者からOpenAI Codexの認証トークンを盗むように設計されています。報告時点では、このパッケージはまだダウンロード可能であり、継続的な脅威となっています。codexui-androidをインストールした開発者は、直ちにトークンをローテーションし、システムに不正アクセスがないか監査することを推奨します。

このインシデントは、オープンソースエコシステムにおけるサプライチェーン攻撃の持続的なリスクを浮き彫りにしています。正規のパッケージ名と高いダウンロード数は、開発者に誤った安心感を与える可能性があります。組織は厳格なパッケージ審査プロセスを実施し、異常なパッケージ動作を検出するツールの使用を検討すべきです。

{{< netrunner-insight >}}

SOCアナリストとDevSecOpsエンジニアにとって、この攻撃はnpmパッケージのダウンロードと動作を監視する必要性を強調しています。予期しないトークンの流出を検出するランタイム検出を実装し、APIトークンへの最小権限アクセスを適用してください。ソフトウェアサプライチェーンを定期的に監査し、パッケージ整合性検証ツールの使用を検討してください。

{{< /netrunner-insight >}}

---

**[完全な記事を The Hacker News で読む ›](https://thehackernews.com/2026/06/openai-codex-authentication-tokens.html)**
