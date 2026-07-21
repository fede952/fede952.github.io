---
title: "WordPress RCE、SonicWall 0-Day、SharePoint 0-Day：今週のセキュリティまとめ"
date: "2026-07-21T09:25:16Z"
original_date: "2026-07-20T13:32:26"
lang: "ja"
translationKey: "wordpress-rce-sonicwall-0-days-sharepoint-0-day-weekly-security-recap"
slug: "wordpress-rce-sonicwall-0-days-sharepoint-0-day-weekly-security-recap"
author: "NewsBot (Validated by Federico Sella)"
description: "今週の脅威には、WordPress RCE、SonicWall 0-day、AIサービスへの攻撃、SharePoint 0-dayが含まれます。小さな入力がコード実行、メモリ損失、鍵の窃取につながります。"
original_url: "https://thehackernews.com/2026/07/weekly-recap-wordpress-rce-sonicwall-0.html"
source: "The Hacker News"
severity: "Critical"
target: "WordPress、SonicWall、SharePoint、AIサービス"
cve: null
cvss: null
kev: null
tags: ["news", "cybersecurity"]
news-categories: ["cybersecurity"]
layout: "news"
draft: false
---

今週の脅威には、WordPress RCE、SonicWall 0-day、AIサービスへの攻撃、SharePoint 0-dayが含まれます。小さな入力がコード実行、メモリ損失、鍵の窃取につながります。

{{< cyber-report severity="Critical" source="The Hacker News" target="WordPress、SonicWall、SharePoint、AIサービス" >}}

今週のセキュリティ情勢は、広く使用されているプラットフォームに影響を与える複数の重大な脆弱性によって特徴づけられます。WordPressのリモートコード実行（RCE）の欠陥、SonicWallのゼロデイ、SharePointの0-dayが活発に悪用されるか、開示されました。攻撃者は、露出したシステム、弱い入力検証、古いドライバーといった単純な攻撃ベクトルを利用して、コード実行、メモリ破損、認証情報の窃取を達成しています。

{{< ad-banner >}}

従来のソフトウェア脆弱性に加えて、AIサービスが攻撃を受けており、敵対者は偽のプロンプトや公開コードリポジトリを使用してマルウェアを配信しています。共通点は、小さく一見無害な入力が、セキュリティツールの無効化や暗号鍵の外部送信といった壊滅的な結果を引き起こす可能性があることです。

防御側は、特に既知の悪用活動がある脆弱性のパッチ適用を優先する必要があります。SonicWallとSharePointの欠陥は、エンタープライズ環境での広範な展開のため、特に懸念されます。組織はAIサービスの露出を見直し、厳格な入力検証とアクセス制御を実施すべきです。

{{< netrunner-insight >}}

SOCアナリストは、これらの脆弱性に関連する侵害指標、特に異常な外部接続やプロセスメモリダンプを直ちに確認する必要があります。DevSecOpsチームは、AIサービスAPIに対して最小権限を適用し、ランタイムセキュリティ監視を実装して、小さな悪意のある入力による異常な動作を検出する必要があります。

{{< /netrunner-insight >}}

---

**[完全な記事を The Hacker News で読む ›](https://thehackernews.com/2026/07/weekly-recap-wordpress-rce-sonicwall-0.html)**
