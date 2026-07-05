---
title: "TokenLens：JWTデコーダー・デバッガー・署名検証ツール"
description: "どんなJSON Web Tokenもブラウザ内でデコード・デバッグし、Web Crypto APIで署名（HS/RS/ES/PS）を暗号的に検証します。100%クライアントサイド — トークンは端末から一切送信されません。"
date: 2026-07-05
tags: ["jwt", "developer-tools", "security", "privacy"]
keywords: ["jwt デコード", "jwt デバッガー", "jwt 署名 検証", "json web token", "jwt バリデーター", "jwt オンライン デコード", "rs256", "es256", "hs256", "クライアントサイド jwt"]
layout: "tool"
draft: false
tool_file: "/tools/jwt-inspector/"
tool_height: "1200"
schema_json: >
  {"@context": "https://schema.org", "@type": "SoftwareApplication", "name": "TokenLens — JWTデコーダー・署名検証ツール", "description": "HS・RS・ES・PSアルゴリズムに対応した、無料・クライアントサイドのJWTデコーダー、クレームデバッガー、Web Crypto署名検証ツール。", "applicationCategory": "DeveloperApplication", "operatingSystem": "Web", "browserRequirements": "Requires JavaScript", "isAccessibleForFree": true, "offers": {"@type": "Offer", "price": "0", "priceCurrency": "USD"}}
---

## TokenLensでできること

TokenLensは、あらゆるJSON Web Tokenをブラウザ内で直接デコードし、ヘッダー・ペイロード・登録済みクレームをわかりやすく表示します — issuer、subject、audience、そしてトークンが発行・有効化・失効する正確なローカル時刻まで。さらに、自分のシークレットや公開鍵を使い、Web Crypto APIで**署名を暗号的に検証**できます。

サーバー型デコーダーと違い、トークンはこのページから決して外に出ません。アップロードも、ログも、ネットワークリクエストもありません。本番のクレームや個人情報を含むトークンを他社のサーバーに貼り付けたくない場合に、まさに必要な仕組みです。

## 対応アルゴリズム

- **HMAC** — HS256、HS384、HS512（共有シークレットで検証）
- **RSA** — RS256/384/512 と PS256/384/512（PEM公開鍵またはJWKで検証）
- **ECDSA** — ES256、ES384、ES512（EC公開鍵またはJWKで検証）

トークンを貼り付けて開始するか、サンプルを読み込んで検証済みのHS256署名をご覧ください。
