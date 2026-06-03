---
title: "未パッチのWindows Search URIハンドラの欠陥によりNTLMv2ハッシュが漏洩"
date: "2026-06-03T11:53:18Z"
original_date: "2026-06-03T10:18:52"
lang: "ja"
translationKey: "unpatched-windows-search-uri-flaw-leaks-ntlmv2-hashes"
author: "NewsBot (Validated by Federico Sella)"
description: "研究者らが、Windows Search: URIハンドラの未パッチの脆弱性を開示。CVE-2026-33829 Snipping Toolの欠陥と同様に、NTLMv2ハッシュを露出させる可能性がある。"
original_url: "https://thehackernews.com/2026/06/unpatched-windows-search-uri.html"
source: "The Hacker News"
severity: "High"
target: "Windows Search: URIハンドラ"
cve: null
cvss: null
kev: null
tags: ["news", "cybersecurity"]
news-categories: ["cybersecurity"]
layout: "news"
draft: false
---

研究者らが、Windows Search: URIハンドラの未パッチの脆弱性を開示。CVE-2026-33829 Snipping Toolの欠陥と同様に、NTLMv2ハッシュを露出させる可能性がある。

{{< cyber-report severity="High" source="The Hacker News" target="Windows Search: URIハンドラ" >}}

Huntressのサイバーセキュリティ研究者らは、Windows Search: URIハンドラの未パッチの脆弱性の詳細を開示した。この脆弱性により、攻撃者がNTLMv2ハッシュを盗む可能性がある。この問題は、Windows Snipping Toolのms-screensketch: URIハンドラにおけるなりすまし脆弱性CVE-2026-33829を彷彿とさせるもので、こちらもNTLMハッシュを露出させていた。

{{< ad-banner >}}

新たに特定された欠陥は、Windows Searchクエリを起動するために使用されるsearch: URIスキームに存在する。search: URIハンドラをトリガーする悪意のあるリンクやファイルを作成することで、攻撃者は標的システムにリモートサーバーへの認証を強制し、ユーザーのNTLMv2ハッシュを漏洩させる。このハッシュはオフラインで解読されたり、リレー攻撃に使用されたりする可能性がある。

公開日時点で、Microsoftから公式パッチはリリースされていない。組織はアップデートを監視し、修正が利用可能になるまでグループポリシーやエンドポイントセキュリティツールを介してsearch: URIハンドラをブロックすることを推奨する。

{{< netrunner-insight >}}

これは古典的なNTLMリレーベクターであり、SOCアナリストは認証ログで監視すべきである。DevSecOpsエンジニアは、環境内のURIハンドラの使用を直ちにレビューし、NTLMv2の無効化やSMB署名の強制などの緩和策の適用を検討すべきである。Microsoftがパッチを提供するまで、search: URIは認情報窃取の潜在的なエントリポイントであると想定せよ。

{{< /netrunner-insight >}}

---

**[完全な記事を The Hacker News で読む ›](https://thehackernews.com/2026/06/unpatched-windows-search-uri.html)**
