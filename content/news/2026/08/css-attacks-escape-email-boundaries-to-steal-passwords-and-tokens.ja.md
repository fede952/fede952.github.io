---
title: "CSS攻撃がメールの境界を越え、パスワードとトークンを窃取"
date: "2026-08-09T07:52:16Z"
original_date: "2026-08-08T08:03:57"
lang: "ja"
translationKey: "css-attacks-escape-email-boundaries-to-steal-passwords-and-tokens"
slug: "css-attacks-escape-email-boundaries-to-steal-passwords-and-tokens"
author: "NewsBot (Validated by Federico Sella)"
description: "新しい研究により、CSSベースの攻撃がメールコンテンツから飛び出してウェブメールのインターフェースを乗っ取り、主要プロバイダー全体で認証情報とトークンを窃取することが明らかになりました。"
original_url: "https://thehackernews.com/2026/08/new-css-attacks-can-break-webmail.html"
source: "The Hacker News"
severity: "High"
target: "ウェブメールインターフェース（Outlook、Gmailなど）"
cve: null
cvss: null
kev: null
tags: ["news", "cybersecurity"]
news-categories: ["cybersecurity"]
layout: "news"
draft: false
---

新しい研究により、CSSベースの攻撃がメールコンテンツから飛び出してウェブメールのインターフェースを乗っ取り、主要プロバイダー全体で認証情報とトークンを窃取することが明らかになりました。

{{< cyber-report severity="High" source="The Hacker News" target="ウェブメールインターフェース（Outlook、Gmailなど）" >}}

セキュリティ研究者のGareth（PortSwigger所属）は、CSSを利用してメールコンテンツと周囲のウェブメールインターフェースとの間の意図された分離を破る、新しいクラスの攻撃を発見しました。悪意のあるメールを作成することで、攻撃者はコンテンツをメッセージの境界から逃がし、ウェブメール自身のUIに干渉させ、パスワードの取得、セッショントークンの窃取、信頼されたユーザー操作の乗っ取りを引き起こす可能性があります。

{{< ad-banner >}}

この研究は、Outlook、Gmail、Fastmail、Proton Mail、Yahoo Mail、AOL Mailを含む主要なウェブメールプロバイダーに影響を与える攻撃チェーンを示しています。認証情報の窃取に加えて、これらの技術は第三者アカウントの乗っ取り、機密トークンの漏えい、さらにはメールを読むAIツールの操作にも使用でき、攻撃対象領域を大幅に拡大します。

これらの発見は、ウェブメールクライアントが信頼できないコンテンツをレンダリングする際の根本的な弱点を浮き彫りにしています。特定のCVEはまだ割り当てられていませんが、影響は深刻であり、ウェブメールに依存する組織は更新を監視し、潜在的な悪用を軽減するために追加のセキュリティ層を検討すべきです。

{{< netrunner-insight >}}

この研究は、メールがマルウェアのベクターであるだけでなく、ユーザーが信頼するインターフェース自体に対する武器にもなり得ることを強調しています。SOCアナリストは、不審なメールをフィッシングの餌としてだけでなく、UIを破壊する可能性のあるペイロードとして扱うべきです。DevSecOpsチームは、ウェブメールクライアントがコンテンツをどのようにサンドボックス化しているかを確認し、CSSベースの突破試行を制限するために厳格なContent Security Policy（CSP）ヘッダーの適用を検討すべきです。

{{< /netrunner-insight >}}

---

**[完全な記事を The Hacker News で読む ›](https://thehackernews.com/2026/08/new-css-attacks-can-break-webmail.html)**
