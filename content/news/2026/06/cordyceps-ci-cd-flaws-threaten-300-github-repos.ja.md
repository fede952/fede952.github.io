---
title: "Cordyceps CI/CDの脆弱性が300以上のGitHubリポジトリを脅かす"
date: "2026-06-25T10:14:17Z"
original_date: "2026-06-24T12:48:11"
lang: "ja"
translationKey: "cordyceps-ci-cd-flaws-threaten-300-github-repos"
author: "NewsBot (Validated by Federico Sella)"
description: "Cordycepsと名付けられた新しいCI/CDワークフローの弱点により、攻撃者がワークフローを乗っ取り、主要組織のオープンソースサプライチェーンを危険にさらす可能性があります。"
original_url: "https://thehackernews.com/2026/06/cordyceps-cicd-flaws-expose-300-github.html"
source: "The Hacker News"
severity: "Critical"
target: "GitHub上のCI/CDワークフロー"
cve: null
cvss: null
kev: null
tags: ["news", "cybersecurity"]
news-categories: ["cybersecurity"]
layout: "news"
draft: false
---

Cordycepsと名付けられた新しいCI/CDワークフローの弱点により、攻撃者がワークフローを乗っ取り、主要組織のオープンソースサプライチェーンを危険にさらす可能性があります。

{{< cyber-report severity="Critical" source="The Hacker News" target="GitHub上のCI/CDワークフロー" >}}

Novee Securityのサイバーセキュリティ研究者は、Cordycepsと名付けられたCI/CDワークフローにおける重大な悪用可能なパターンを特定しました。これにより、攻撃者はワークフローを乗っ取り、オープンソースサプライチェーンを危険にさらす可能性があります。この欠陥は、Microsoft、Google、Apacheなどの主要組織に属する300以上のGitHubリポジトリに影響を与えます。

{{< ad-banner >}}

Cordycepsパターンにより、攻撃者はリポジトリを完全に制御でき、不正なコード変更、バックドアの挿入、下流のサプライチェーン攻撃につながる可能性があります。この脆弱性は、入力を適切に分離または検証できない安全でないワークフロー設定に起因します。

GitHub Actionsまたは同様のCI/CDプラットフォームを使用する組織は、Cordycepsパターンについてワークフロー定義を確認し、最小権限の許可、入力のサニタイズ、環境の分離を実装してリスクを軽減することを推奨します。

{{< netrunner-insight >}}

これは典型的なサプライチェーン攻撃ベクトルです。SOCアナリストは、異常なワークフロー実行や予期しないリポジトリ変更を監視する必要があります。DevSecOpsチームは、信頼できない入力の処理と権限のスコープ設定に焦点を当てて、CI/CDパイプラインの設定を直ちに監査する必要があります。

{{< /netrunner-insight >}}

---

**[完全な記事を The Hacker News で読む ›](https://thehackernews.com/2026/06/cordyceps-cicd-flaws-expose-300-github.html)**
