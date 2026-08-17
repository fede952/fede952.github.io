---
title: "PyPI上の悪意あるLiteLLMリリース、Trivyハッキングに関連し2,100以上の組織が露出"
date: "2026-08-17T07:48:06Z"
original_date: "2026-08-12T08:04:52"
lang: "ja"
translationKey: "malicious-litellm-releases-on-pypi-linked-to-trivy-hack-expose-2100-orgs"
slug: "malicious-litellm-releases-on-pypi-linked-to-trivy-hack-expose-2100-orgs"
author: "NewsBot (Validated by Federico Sella)"
description: "PyPI上の2つの悪意あるLiteLLMパッケージが、クラウドキーやSSHキーなどを窃取。CloudSEKのデータによると、2,100以上の組織が影響を受ける可能性があります。"
original_url: "https://thehackernews.com/2026/08/malicious-litellm-releases-tied-to.html"
source: "The Hacker News"
severity: "High"
target: "PyPI上のLiteLLMユーザー"
cve: null
cvss: null
kev: null
tags: ["news", "cybersecurity"]
news-categories: ["cybersecurity"]
layout: "news"
draft: false
---

PyPI上の2つの悪意あるLiteLLMパッケージが、クラウドキーやSSHキーなどを窃取。CloudSEKのデータによると、2,100以上の組織が影響を受ける可能性があります。

{{< cyber-report severity="High" source="The Hacker News" target="PyPI上のLiteLLMユーザー" >}}

3月に、2つの悪意あるLiteLLMリリースがPyPIに公開され、約40分間利用可能でした。これらのパッケージには、資格情報を窃取するコードが含まれており、インストールしたシステムからクラウドアクセスキー、SSH秘密鍵、Kubernetesトークン、データベースパスワードなど、さまざまな秘密情報を収集するように設計されていました。

{{< ad-banner >}}

脅威インテリジェンス企業CloudSEKは、攻撃者が取得した約434,000ファイルから構築されたデータセットを入手しました。このデータセットの分析により、影響は2,100以上の組織に及ぶ可能性があり、侵害の潜在的な規模が浮き彫りになっています。

このインシデントは、以前のTrivyハッキングに関連しており、調整されたサプライチェーン攻撃を示しています。影響を受けた期間中にPyPIからLiteLLMをインストールした組織は、露出したすべての資格情報を直ちにローテーションし、不正アクセスの兆候がないか調査する必要があります。

{{< netrunner-insight >}}

このインシデントは、ソフトウェアサプライチェーンへの警戒が極めて重要であることを強調しています。SOCアナリストは、悪意あるLiteLLMバージョンのインストールを監視し、潜在的に露出した秘密情報の資格情報ローテーションを優先すべきです。DevSecOpsチームは、厳格なパッケージ整合性チェックを実施し、ハッシュ付きロックファイルやプライベートミラーを使用して、このようなリスクを軽減することを検討すべきです。

{{< /netrunner-insight >}}

---

**[完全な記事を The Hacker News で読む ›](https://thehackernews.com/2026/08/malicious-litellm-releases-tied-to.html)**
