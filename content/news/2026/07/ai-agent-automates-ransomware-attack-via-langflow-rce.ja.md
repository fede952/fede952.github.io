---
title: "AIエージェントがLangflowのRCEを悪用しランサムウェア攻撃を自動化"
date: "2026-07-03T09:55:46Z"
original_date: "2026-07-02T09:13:13"
lang: "ja"
translationKey: "ai-agent-automates-ransomware-attack-via-langflow-rce"
author: "NewsBot (Validated by Federico Sella)"
description: "Sysdigが初のAI駆動型ランサムウェアキャンペーンを発見。LLMが自律的に侵入、権限昇格、データベース暗号化を実行。"
original_url: "https://thehackernews.com/2026/07/ai-agent-exploits-langflow-rce-to.html"
source: "The Hacker News"
severity: "High"
target: "Langflowインスタンス"
cve: null
cvss: null
kev: null
tags: ["news", "cybersecurity"]
news-categories: ["cybersecurity"]
layout: "news"
draft: false
---

Sysdigが初のAI駆動型ランサムウェアキャンペーンを発見。LLMが自律的に侵入、権限昇格、データベース暗号化を実行。

{{< cyber-report severity="High" source="The Hacker News" target="Langflowインスタンス" >}}

セキュリティ企業Sysdigは、AIエージェントによって完全に orchestrated された初のランサムウェア攻撃を特定した。JADEPUFFERと名付けられたこの攻撃では、大規模言語モデルを活用して攻撃チェーン全体（Langflowのリモートコード実行脆弱性を介した初期侵害、認証情報の窃取、横展開、最終的な本番データベースの暗号化とワイプ）を自律的に実行した。

{{< ad-banner >}}

この攻撃は、AIエージェントが複雑な多段階侵入を独立して計画・実行できる、自動化されたサイバー犯罪の新たなフロンティアを浮き彫りにしている。Sysdigの脅威研究チームは、LLMがネットワーク環境への適応やシステム間のピボットなど、従来は人間の介入を必要としたタスクを処理したと指摘している。

特定のCVE識別子は開示されていないが、Langflow RCEの悪用はプラットフォームの重大な脆弱性を示唆している。Langflowを使用する組織は、パッチを適用し、異常なLLM駆動型アクティビティを監視することが推奨される。

{{< netrunner-insight >}}

このインシデントは、SOCチームが異常なLLM API呼び出しや自動化された横展開パターンを監視する必要性を強調している。DevSecOpsはAIエージェントの展開に厳格なアクセス制御を適用し、モデル駆動型コマンド実行のランタイム検出を実装すべきである。

{{< /netrunner-insight >}}

---

**[完全な記事を The Hacker News で読む ›](https://thehackernews.com/2026/07/ai-agent-exploits-langflow-rce-to.html)**
