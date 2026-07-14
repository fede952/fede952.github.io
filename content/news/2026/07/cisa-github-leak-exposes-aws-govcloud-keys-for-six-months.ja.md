---
title: "CISAのGitHubリークでAWS GovCloudキーが6か月間流出"
date: "2026-07-14T09:01:14Z"
original_date: "2026-07-13T15:03:28"
lang: "ja"
translationKey: "cisa-github-leak-exposes-aws-govcloud-keys-for-six-months"
slug: "cisa-github-leak-exposes-aws-govcloud-keys-for-six-months"
author: "NewsBot (Validated by Federico Sella)"
description: "請負業者がCISAの内部認証情報（AWS GovCloudキーを含む）をGitHubに6か月間漏洩。専門家がセキュリティチームに重要な教訓を指摘。"
original_url: "https://krebsonsecurity.com/2026/07/lessons-learned-from-cisas-recent-github-leak/"
source: "Krebs on Security"
severity: "High"
target: "CISA GitHubリポジトリ"
cve: null
cvss: null
kev: null
tags: ["news", "cybersecurity"]
news-categories: ["cybersecurity"]
layout: "news"
draft: false
---

請負業者がCISAの内部認証情報（AWS GovCloudキーを含む）をGitHubに6か月間漏洩。専門家がセキュリティチームに重要な教訓を指摘。

{{< cyber-report severity="High" source="Krebs on Security" target="CISA GitHubリポジトリ" >}}

サイバーセキュリティ・インフラストラクチャセキュリティ庁（CISA）は、請負業者が誤って数十の内部認証情報（AWS GovCloudキーを含む）を公開GitHubリポジトリに公開したデータ漏洩を開示した。認証情報は、KrebsOnSecurityが当局に通知するまで約6か月間露出したままだった。

{{< ad-banner >}}

CISAの事後分析では、検出の遅れや公開リポジトリのシークレット自動スキャンの欠如など、初期対応のギャップが特定された。このインシデントは、堅牢なシークレット管理とコードリポジトリの継続的な監視の必要性を強調している。

専門家は、プリコミットフック、定期的なシークレットスキャン、厳格なアクセス制御を実装して同様の漏洩を防ぐことを推奨している。一時的な認証情報と自動ローテーションの使用も、露出したキーの影響を軽減できる。

{{< netrunner-insight >}}

このインシデントは、シークレットスキャンをコミット後だけでなくCI/CDパイプラインに統合する必要がある典型的な事例である。SOCアナリストは公開リポジトリの露出に関するアラートを優先し、DevSecOpsチームは請負業者に対して最小権限アクセスを強制すべきである。認証情報のローテーションを自動化し、GitLeaksやTruffleHogなどのツールを使用して早期に漏洩を検出することを検討せよ。

{{< /netrunner-insight >}}

---

**[完全な記事を Krebs on Security で読む ›](https://krebsonsecurity.com/2026/07/lessons-learned-from-cisas-recent-github-leak/)**
