---
title: "サプライチェーン攻撃でMiasmaワームがMicrosoftの73のGitHubリポジトリを侵害"
date: "2026-06-07T09:57:27Z"
original_date: "2026-06-06T06:58:04"
lang: "ja"
translationKey: "miasma-worm-hits-73-microsoft-github-repos-in-supply-chain-attack"
author: "NewsBot (Validated by Federico Sella)"
description: "MicrosoftのAzure、Azure-Samples、Microsoft、MicrosoftDocsにわたるGitHubリポジトリが、自己複製型ワームMiasmaによって侵害され、73のリポジトリが影響を受けました。"
original_url: "https://thehackernews.com/2026/06/miasma-worm-hits-73-microsoft-github.html"
source: "The Hacker News"
severity: "High"
target: "MicrosoftのGitHubリポジトリ"
cve: null
cvss: null
kev: null
tags: ["news", "cybersecurity"]
news-categories: ["cybersecurity"]
layout: "news"
draft: false
---

MicrosoftのAzure、Azure-Samples、Microsoft、MicrosoftDocsにわたるGitHubリポジトリが、自己複製型ワームMiasmaによって侵害され、73のリポジトリが影響を受けました。

{{< cyber-report severity="High" source="The Hacker News" target="MicrosoftのGitHubリポジトリ" >}}

自己複製型のサプライチェーン攻撃キャンペーンMiasmaは、MicrosoftのGitHubリポジトリを標的に拡大し、Azure、Azure-Samples、Microsoft、MicrosoftDocsの4つの組織にわたる73のリポジトリを侵害しました。このインシデントはOpenSourceMalwareによって報告され、GitHubは拡散を封じ込めるため、影響を受けたリポジトリへのアクセスを無効化しました。

{{< ad-banner >}}

この攻撃は、ソフトウェアサプライチェーンにおける自己複製型マルウェアの脅威の増大を浮き彫りにしています。信頼されたリポジトリを侵害することで、攻撃者はこれらのソースに依存する下流プロジェクトに悪意のあるコードを注入し、広範囲のユーザーや組織に影響を及ぼす可能性があります。

侵害の具体的な技術的詳細は明らかにされていませんが、このインシデントはCI/CDパイプラインやリポジトリ管理におけるセキュリティ対策の強化の必要性を強調しています。組織はMicrosoftのGitHubリポジトリへの依存関係を確認し、異常な活動を監視する必要があります。

{{< netrunner-insight >}}

SOCアナリストは、自身のGitHub組織における異常なコミットやアクセスパターンの監視を優先してください。DevSecOpsチームは、厳格なブランチ保護ルールを適用し、署名付きコミットを必須とし、CI/CDパイプラインでの自己複製型マルウェアの自動スキャンを実装すべきです。このインシデントは、Microsoftのような大手ベンダーでさえサプライチェーン攻撃の影響を受けないわけではないという厳しい教訓です。

{{< /netrunner-insight >}}

---

**[完全な記事を The Hacker News で読む ›](https://thehackernews.com/2026/06/miasma-worm-hits-73-microsoft-github.html)**
