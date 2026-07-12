---
title: "偽のMicrosoft Entraパスキー登録がM365ユーザーを標的にしたデータ恐喝キャンペーン"
date: "2026-07-12T09:00:42Z"
original_date: "2026-07-10T10:30:20"
lang: "ja"
translationKey: "fake-microsoft-entra-passkey-enrollment-targets-m365-users-in-data-extortion-campaign"
slug: "fake-microsoft-entra-passkey-enrollment-targets-m365-users-in-data-extortion-campaign"
author: "NewsBot (Validated by Federico Sella)"
description: "脅威アクターO-UNC-066は音声ベースのフィッシングを使用して、ユーザーを騙して偽のEntraパスキーを登録させ、Microsoft 365アカウントを侵害してデータ恐喝を試みています。"
original_url: "https://thehackernews.com/2026/07/hackers-use-fake-microsoft-entra.html"
source: "The Hacker News"
severity: "High"
target: "Microsoft 365ユーザー"
cve: null
cvss: null
kev: null
tags: ["news", "cybersecurity"]
news-categories: ["cybersecurity"]
layout: "news"
draft: false
---

脅威アクターO-UNC-066は音声ベースのフィッシングを使用して、ユーザーを騙して偽のEntraパスキーを登録させ、Microsoft 365アカウントを侵害してデータ恐喝を試みています。

{{< cyber-report severity="High" source="The Hacker News" target="Microsoft 365ユーザー" >}}

OktaによってO-UNC-066として追跡されている脅威アクターが、複数のセクターにわたるMicrosoft 365ユーザーを標的にした音声ベースのフィッシング攻撃を行っていることが確認されました。攻撃者は正当なセキュリティリクエストを装い、被害者を騙して偽のEntraパスキーを登録させ、それによってアカウントへの不正アクセスを獲得します。

{{< ad-banner >}}

このキャンペーンでは、パスキー登録プロセスを傍受するために特別に設計されたパネル制御のフィッシングキットが使用されています。攻撃者がアクセスを獲得すると、データ恐喝を実行し、機密情報を流出させて身代金を要求することを目的としています。これらの攻撃は、従来のメールベースのフィッシング防御を回避するために音声チャネルを使用するという増加傾向を浮き彫りにしています。

組織は、ハードウェアセキュリティキーを使用した多要素認証（MFA）を実装し、ユーザーに対して、別の通信チャネルを介して不審なセキュリティリクエストを確認するよう教育することを推奨します。異常なパスキー登録アクティビティを監視することで、このような攻撃を早期に検出できます。

{{< netrunner-insight >}}

この攻撃は、音声ベースのセキュリティリクエストをフィッシングメールと同様の疑いの目で扱うことの重要性を強調しています。SOCアナリストは、異常なパスキー登録試行を監視し、MFA登録プロセスが帯域外検証を必要とすることを確認する必要があります。DevSecOpsチームは、パスキー登録を信頼できるデバイスと場所に制限する条件付きアクセスポリシーの実装を検討すべきです。

{{< /netrunner-insight >}}

---

**[完全な記事を The Hacker News で読む ›](https://thehackernews.com/2026/07/hackers-use-fake-microsoft-entra.html)**
