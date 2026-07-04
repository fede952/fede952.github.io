---
title: "PamStealer macOSスティーラー、偽のMaccyサイトとPAMチェックを悪用"
date: "2026-07-04T09:17:53Z"
original_date: "2026-07-03T08:03:37"
lang: "ja"
translationKey: "pamstealer-macos-stealer-uses-fake-maccy-sites-and-pam-checks"
author: "NewsBot (Validated by Federico Sella)"
description: "Jamf Threat Labsが、偽のMaccyサイトを介して配布されるmacOS情報スティーラーPamStealerを発見。PAMチェックを利用してログインパスワードを窃取する。"
original_url: "https://thehackernews.com/2026/07/pamstealer-uses-fake-maccy-sites-and.html"
source: "The Hacker News"
severity: "High"
target: "macOSユーザー"
cve: null
cvss: null
kev: null
tags: ["news", "cybersecurity"]
news-categories: ["cybersecurity"]
layout: "news"
draft: false
---

Jamf Threat Labsが、偽のMaccyサイトを介して配布されるmacOS情報スティーラーPamStealerを発見。PAMチェックを利用してログインパスワードを窃取する。

{{< cyber-report severity="High" source="The Hacker News" target="macOSユーザー" >}}

Jamf Threat Labsのサイバーセキュリティ研究者は、PamStealerと名付けられた新しいmacOS情報スティーラーを特定しました。このマルウェアは、正規のオープンソースクリップボードマネージャーであるMaccyを装ったコンパイル済みAppleScript（.scpt）ファイルとして配布されます。感染して機密データ（ログインパスワードを含む）を吸い上げるために、巧妙な一連のトリックを仕掛けます。

{{< ad-banner >}}

PamStealerという名前は、macOSのPluggable Authentication Module（PAM）フレームワークを悪用する能力に由来します。認証プロセスを傍受することで、ユーザーがログインしたり特権操作のために認証したりする際に、認証情報をキャプチャできます。その後、スティーラーは盗んだデータを攻撃者が管理するサーバーに流出させます。

このキャンペーンは、偽のWebサイトとソーシャルエンジニアリングに依存して、ユーザーを騙して悪意のある.scptファイルをダウンロードさせます。実行されると、マルウェアはPAMチェックを実行して、疑われることなくパスワードを収集します。macOSエンドポイントを抱える組織は、異常な.scptファイルの実行やPAM関連の異常を監視する必要があります。

{{< netrunner-insight >}}

SOCアナリストにとって、これはmacOSエンドポイントでのコンパイル済みAppleScriptの実行やPAMの変更を監視する必要性を浮き彫りにしています。DevSecOpsチームはアプリケーションホワイトリストを実施し、特にクリップボードマネージャーについて、ソフトウェアの入手元を確認するようユーザーを教育すべきです。PAMの悪用に対するエンドポイント検出ルールを実装することで、このスティーラーを早期に発見できます。

{{< /netrunner-insight >}}

---

**[完全な記事を The Hacker News で読む ›](https://thehackernews.com/2026/07/pamstealer-uses-fake-maccy-sites-and.html)**
