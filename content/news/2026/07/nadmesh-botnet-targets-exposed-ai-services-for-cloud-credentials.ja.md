---
title: "NadMeshボットネット、露出したAIサービスを標的にクラウド認証情報を窃取"
date: "2026-07-19T09:05:56Z"
original_date: "2026-07-17T17:12:23"
lang: "ja"
translationKey: "nadmesh-botnet-targets-exposed-ai-services-for-cloud-credentials"
slug: "nadmesh-botnet-targets-exposed-ai-services-for-cloud-credentials"
author: "NewsBot (Validated by Federico Sella)"
description: "Goで書かれた新しいボットネットNadMeshが、ComfyUIやOllamaなどの露出したAIプラットフォームを探索し、AWSキーやKubernetesトークンを盗んでいます。3,800以上のキーが盗まれたと報告されています。"
original_url: "https://thehackernews.com/2026/07/new-nadmesh-botnet-hunts-exposed-ai.html"
source: "The Hacker News"
severity: "High"
target: "露出したAIサービス（ComfyUI、Ollama、n8nなど）"
cve: null
cvss: null
kev: null
tags: ["news", "cybersecurity"]
news-categories: ["cybersecurity"]
layout: "news"
draft: false
---

Goで書かれた新しいボットネットNadMeshが、ComfyUIやOllamaなどの露出したAIプラットフォームを探索し、AWSキーやKubernetesトークンを盗んでいます。3,800以上のキーが盗まれたと報告されています。

{{< cyber-report severity="High" source="The Hacker News" target="露出したAIサービス（ComfyUI、Ollama、n8nなど）" >}}

NadMeshと名付けられた新しいGo製ボットネットが2026年7月初旬に出現し、露出したAIサービスを標的にクラウド認証情報とKubernetesトークンを盗んでいます。ボットネットのオペレーターダッシュボードには3,811のユニークなAWSキーが収穫されたと表示されており、大規模な運用規模を示しています。NadMeshはShodanベースのハーベスターを使用して、ComfyUI、Ollama、n8n、Open WebUI、Langflow、Gradioなどの人気AIツールの脆弱なインスタンスでスキャンキューを継続的に補充しています。

{{< ad-banner >}}

これらのAIプラットフォームは、開発チームによって適切なセキュリティ強化なしに迅速にデプロイされることが多く、インターネットに露出したままになっています。ボットネットはこのファイアウォール保護の欠如を悪用してアクセスを取得し、機密性の高い認証情報を抽出します。AIサービスへの焦点は、攻撃者の標的が価値の高いクラウドインフラストラクチャや機械学習パイプラインに移行していることを示唆しています。

これらのAIツールを実行している組織は、すぐに露出を監査し、ネットワークアクセスを制限し、侵害された可能性のある認証情報をローテーションする必要があります。NadMeshボットネットは、設定ミスのあるAIサービスが認証情報の窃取や横方向の移動の主要な標的となる、脅威の状況の拡大を示しています。

{{< netrunner-insight >}}

SOCアナリスト向け：環境内で露出したComfyUI、Ollama、および類似のAIサービスをスキャンすることを優先してください。DevSecOpsチームは、これらのツールをデプロイする前にネットワークセグメンテーションとファイアウォールルールを適用する必要があります。NadMeshボットネットは、セキュリティレビューなしの迅速なデプロイが自動化された認証情報収穫を招くことを明確に示しています。

{{< /netrunner-insight >}}

---

**[完全な記事を The Hacker News で読む ›](https://thehackernews.com/2026/07/new-nadmesh-botnet-hunts-exposed-ai.html)**
