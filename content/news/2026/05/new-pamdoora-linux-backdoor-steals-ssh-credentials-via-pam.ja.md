---
title: "新しいLinuxバックドア「PamDOORa」がPAMを介してSSH認証情報を窃取"
date: "2026-05-09T08:29:08Z"
original_date: "2026-05-08T08:41:00"
lang: "ja"
translationKey: "new-pamdoora-linux-backdoor-steals-ssh-credentials-via-pam"
author: "NewsBot (Validated by Federico Sella)"
description: "PamDOORaと名付けられた新しいLinuxバックドアが、ロシアのサイバー犯罪フォーラムで1,600ドルで販売されています。このバックドアはPAMモジュールを使用し、マジックパスワードとTCPポートの組み合わせで永続的なSSHアクセスを提供します。"
original_url: "https://thehackernews.com/2026/05/new-linux-pamdoora-backdoor-uses-pam.html"
source: "The Hacker News"
severity: "High"
target: "Linux SSHサーバー"
cve: null
cvss: null
kev: null
tags: ["news", "cybersecurity"]
news-categories: ["cybersecurity"]
layout: "news"
draft: false
---

PamDOORaと名付けられた新しいLinuxバックドアが、ロシアのサイバー犯罪フォーラムで1,600ドルで販売されています。このバックドアはPAMモジュールを使用し、マジックパスワードとTCPポートの組み合わせで永続的なSSHアクセスを提供します。

{{< cyber-report severity="High" source="The Hacker News" target="Linux SSHサーバー" >}}

サイバーセキュリティ研究者は、PamDOORaと呼ばれる新しいLinuxバックドアを発見しました。これは、脅威アクター「darkworm」によってロシアのサイバー犯罪フォーラムRehubで1,600ドルで販売されています。このバックドアは、Pluggable Authentication Module（PAM）ベースのポストエクスプロイテーションツールキットとして設計されており、マジックパスワードと特定のTCPポートの組み合わせにより永続的なSSHアクセスを可能にします。

{{< ad-banner >}}

PamDOORaは、悪意のあるPAMモジュールを介してSSH認証を傍受し、攻撃者が通常の認証情報をバイパスして不正アクセスを獲得することを可能にします。PAMモジュールを使用することで、バックドアはLinuxシステムの標準認証フローに統合されるため、ステルス性が高まります。

このようなツールがサイバー犯罪フォーラムで販売されていることは、高度な攻撃ツールの商品化が進んでいることを示しています。組織は、異常なSSH認証パターンを監視し、PAM構成を定期的に監査することを推奨します。

{{< netrunner-insight >}}

SOCアナリストにとって、PamDOORaを検出するには、非標準ポートでの予期しないSSH接続を監視し、PAMモジュールの変更と関連付ける必要があります。DevSecOpsチームは、厳格なPAM構成管理を実施し、/etc/pam.d/および関連ライブラリのファイル整合性監視を検討すべきです。このバックドアは、PAMを重要なセキュリティ境界として扱うことの重要性を強調しています。

{{< /netrunner-insight >}}

---

**[完全な記事を The Hacker News で読む ›](https://thehackernews.com/2026/05/new-linux-pamdoora-backdoor-uses-pam.html)**
