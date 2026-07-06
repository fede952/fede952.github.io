---
title: "SafeEnv：.envファイルのシークレット＆APIキースキャナー"
description: "コミット前に .env ファイルや設定スニペットを検査して、露出したシークレットを検出 — AWSキー、GitHub・Stripeトークン、秘密鍵、URL内のパスワード、高エントロピー値。100%ブラウザ内で動作し、何もアップロードされません。"
date: 2026-07-05
tags: ["security", "developer-tools", "secrets", "privacy"]
keywords: ["envファイル スキャナー", "シークレット スキャナー", "apiキー チェック", "漏洩シークレット 検出", "env スキャン", "awsキー 漏洩", "git secrets", "クライアントサイド シークレットスキャナー", "dotenv セキュリティ"]
layout: "tool"
draft: false
tool_file: "/tools/secrets-scanner/"
tool_height: "1150"
schema_json: >
  {"@context": "https://schema.org", "@type": "SoftwareApplication", "name": "SafeEnv — シークレット＆APIキースキャナー", "description": "コミット前に .env や設定ファイル内の露出したAPIキー・トークン・秘密鍵・パスワードを見つける、無料のクライアントサイドスキャナー。", "applicationCategory": "SecurityApplication", "operatingSystem": "Web", "browserRequirements": "Requires JavaScript", "isAccessibleForFree": true, "offers": {"@type": "Offer", "price": "0", "priceCurrency": "USD"}}
---

## なぜコミット前にスキャンするのか

公開リポジトリに `.env` を1つ貼っただけで手遅れになります。ボットはGitHubを巡回し、新しいAWSキーを**1分以内**に見つけ出します。SafeEnvはコミット前に漏洩を捕捉。`.env`、`docker-compose.yml`、CI設定、コード断片など任意の設定を貼り付けると、露出した認証情報を行番号・マスク済みプレビュー・具体的な対処手順つきで警告します。

スキャンはこのページのメモリ内だけで実行されます。アップロードも、ログも、ネットワークリクエストもありません。本物のシークレットを貼り付けるツールとして、それ以外の設計はあり得ません。ページを再読み込みすれば全て消えます。

## 検出対象

- **クラウド・APIトークン** — AWSキー、GitHub、GitLab、Stripe、Google、OpenAI、Anthropic、Slack、SendGrid、npm、PyPI、Telegram、Twilio
- **秘密鍵** — RSA/EC/OpenSSH/PGP の PEM ブロック
- **URL内の認証情報** — パスワード入りのデータベース接続文字列や basic-auth URL
- **一般的な漏洩** — ハードコードされたパスワードや高エントロピー値。プレースホルダー判定で誤検出を抑制

設定を貼り付けてスキャンするか、サンプルを読み込んで全検出器が偽キーに反応する様子をご覧ください。
