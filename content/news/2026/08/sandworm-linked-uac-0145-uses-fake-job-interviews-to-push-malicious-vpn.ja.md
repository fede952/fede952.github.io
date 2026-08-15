---
title: "Sandworm関連のUAC-0145、偽の就職面接を利用して悪意のあるVPNを配布"
date: "2026-08-15T07:23:49Z"
original_date: "2026-08-11T18:36:47"
lang: "ja"
translationKey: "sandworm-linked-uac-0145-uses-fake-job-interviews-to-push-malicious-vpn"
slug: "sandworm-linked-uac-0145-uses-fake-job-interviews-to-push-malicious-vpn"
author: "NewsBot (Validated by Federico Sella)"
description: "CERT-UAは、ロシアの国家支援を受けた脅威アクターが、偽の就職面接を介してウクライナのITワーカーを標的にし、コマンドを実行できるVPNを配布していると警告しています。"
original_url: "https://thehackernews.com/2026/08/sandworm-linked-uac-0145-uses-fake-job.html"
source: "The Hacker News"
severity: "High"
target: "ウクライナのITワーカー"
cve: null
cvss: null
kev: null
tags: ["news", "cybersecurity"]
news-categories: ["cybersecurity"]
layout: "news"
draft: false
---

CERT-UAは、ロシアの国家支援を受けた脅威アクターが、偽の就職面接を介してウクライナのITワーカーを標的にし、コマンドを実行できるVPNを配布していると警告しています。

{{< cyber-report severity="High" source="The Hacker News" target="ウクライナのITワーカー" >}}

CERT-UAは、ロシアの国家支援グループSandworm (APT44)のサブグループである脅威クラスターUAC-0145に帰属する新しいソーシャルエンジニアリングキャンペーンを公開しました。このキャンペーンは、ウクライナのITワーカーを標的にし、採用担当者を装って被害者を偽の就職面接に誘導します。

{{< ad-banner >}}

面接プロセス中、被害者は、任意のコマンドを実行できるマルウェアであるVPNアプリケーションをインストールするよう騙されます。この手法は、就職採用に関連する信頼を悪用して、ユーザーの防御を回避します。

この活動は、ロシアの国家支援を受けたアクターによるウクライナの組織、特にIT部門に対する進行中のサイバー脅威を浮き彫りにしています。CERT-UAのUAC-0145への帰属は、これらの攻撃の高度で持続的な性質を強調しています。

{{< netrunner-insight >}}

このキャンペーンは、セキュリティ意識の高いITプロフェッショナルでさえも、ソーシャルエンジニアリングがマルウェア配布に効果的であることを示しています。SOCアナリストは、このような採用ベースの誘いについてユーザーを教育し、異常なVPNインストールやコマンド実行を監視する必要があります。DevSecOpsチームは、アプリケーションの許可リストを適用し、署名されていないバイナリの実行を制限して、このような脅威を軽減する必要があります。

{{< /netrunner-insight >}}

---

**[完全な記事を The Hacker News で読む ›](https://thehackernews.com/2026/08/sandworm-linked-uac-0145-uses-fake-job.html)**
