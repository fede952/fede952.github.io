---
title: "CISA請負業者がAWS GovCloudキーをGitHubで漏洩"
date: "2026-05-19T10:35:27Z"
original_date: "2026-05-18T20:48:21"
lang: "ja"
translationKey: "cisa-contractor-leaks-aws-govcloud-keys-on-github"
author: "NewsBot (Validated by Federico Sella)"
description: "CISAの請負業者が、公開GitHubリポジトリにAWS GovCloudの認証情報と内部ビルド詳細を公開し、最も深刻な政府データ漏洩の一つとなった。"
original_url: "https://krebsonsecurity.com/2026/05/cisa-admin-leaked-aws-govcloud-keys-on-github/"
source: "Krebs on Security"
severity: "Critical"
target: "CISA AWS GovCloudアカウント"
cve: null
cvss: null
kev: null
tags: ["news", "cybersecurity"]
news-categories: ["cybersecurity"]
layout: "news"
draft: false
---

CISAの請負業者が、公開GitHubリポジトリにAWS GovCloudの認証情報と内部ビルド詳細を公開し、最も深刻な政府データ漏洩の一つとなった。

{{< cyber-report severity="Critical" source="Krebs on Security" target="CISA AWS GovCloudアカウント" >}}

先週末まで、サイバーセキュリティ・インフラストラクチャセキュリティ庁（CISA）の請負業者が、複数の高特権AWS GovCloudアカウントと多数の内部CISAシステムへの認証情報を公開したGitHubリポジトリを管理していた。セキュリティ専門家によると、この公開アーカイブには、CISAが内部でソフトウェアを構築、テスト、デプロイする方法を詳述したファイルが含まれており、近年で最も悪質な政府データ漏洩の一つであるという。

{{< ad-banner >}}

漏洩した認証情報により、攻撃者は機密性の高い政府クラウド環境や内部システムにアクセスし、データの流出やさらなる侵害につながる可能性がある。このインシデントは、政府請負業者であっても、公開リポジトリにハードコードされたシークレットのリスクを浮き彫りにしている。

{{< netrunner-insight >}}

この漏洩は、自動シークレットスキャンと厳格なリポジトリアクセス制御の重要性を浮き彫りにしている。SOCアナリストは、公開コードリポジトリでの認証情報漏洩の監視を優先すべきであり、DevSecOpsチームはシークレット管理ポリシーを徹底し、侵害された可能性のあるキーを直ちにローテーションする必要がある。

{{< /netrunner-insight >}}

---

**[完全な記事を Krebs on Security で読む ›](https://krebsonsecurity.com/2026/05/cisa-admin-leaked-aws-govcloud-keys-on-github/)**
