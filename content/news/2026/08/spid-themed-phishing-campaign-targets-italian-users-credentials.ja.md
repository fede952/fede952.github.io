---
title: "SPIDをテーマにしたフィッシングキャンペーンがイタリア人ユーザーの認証情報を標的に"
date: "2026-08-17T07:50:54Z"
original_date: "2026-08-03T11:05:05"
lang: "ja"
translationKey: "spid-themed-phishing-campaign-targets-italian-users-credentials"
slug: "spid-themed-phishing-campaign-targets-italian-users-credentials"
author: "NewsBot (Validated by Federico Sella)"
description: "CERT-AGIDは、SPIDとAgIDのブランドを悪用し、「spid」と「gov」を含むドメインを介して個人情報や銀行情報を窃取する新しいフィッシングキャンペーンについて警告しています。"
original_url: "https://cert-agid.gov.it/news/phishing-a-tema-spid-in-corso/"
source: "CERT-AgID"
severity: "Medium"
target: "イタリアのSPIDユーザー"
cve: null
cvss: null
kev: null
tags: ["news", "cybersecurity"]
news-categories: ["cybersecurity"]
layout: "news"
draft: false
---

CERT-AGIDは、SPIDとAgIDのブランドを悪用し、「spid」と「gov」を含むドメインを介して個人情報や銀行情報を窃取する新しいフィッシングキャンペーンについて警告しています。

{{< cyber-report severity="Medium" source="CERT-AgID" target="イタリアのSPIDユーザー" >}}

CERT-AGIDは、SPID（Sistema Pubblico di Identità Digitale）のテーマを悪用し、イタリア人ユーザーから個人情報や銀行情報を不正に取得する進行中のフィッシングキャンペーンを特定しました。このキャンペーンは、AgIDとSPIDの公式名称とロゴを悪用して信頼性を高めており、特に欺瞞的です。

{{< ad-banner >}}

攻撃者は、「spid」と「gov」という用語を名前に含む複数のドメインを使用しています。これは、ユーザーが正規の政府サービスとやり取りしていると思い込ませるための戦術です。このアプローチは、公式に見えるドメインやブランドに対するユーザーの信頼を悪用します。

正確な攻撃ベクトル（例：電子メール、SMS）は勧告に明記されていませんが、キャンペーンの目的は明確です：機密データの収集です。ユーザーは、個人情報や銀行情報を要求する通信の信頼性を確認し、不審なメッセージを適切な当局に報告することをお勧めします。

{{< netrunner-insight >}}

SOCアナリストにとって、このキャンペーンは、信頼できるブランド用語と「gov」または類似のTLDを組み合わせた類似ドメインを監視することの重要性を強調しています。そのようなドメインを含むメッセージにフラグを立てるメールフィルタリングルールを実装し、ユーザーにクリック前にURLを確認するよう教育してください。DevSecOpsチームは、セキュリティスタックにドメインレピュテーションフィードを統合して、これらのフィッシングドメインを自動的にブロックすることを検討すべきです。

{{< /netrunner-insight >}}

---

**[完全な記事を CERT-AgID で読む ›](https://cert-agid.gov.it/news/phishing-a-tema-spid-in-corso/)**
