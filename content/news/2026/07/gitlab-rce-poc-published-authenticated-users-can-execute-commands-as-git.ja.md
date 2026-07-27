---
title: "GitLab RCE PoC公開：認証ユーザーがgitユーザーとしてコマンド実行可能"
date: "2026-07-27T10:37:15Z"
original_date: "2026-07-25T10:14:26"
lang: "ja"
translationKey: "gitlab-rce-poc-published-authenticated-users-can-execute-commands-as-git"
slug: "gitlab-rce-poc-published-authenticated-users-can-execute-commands-as-git"
author: "NewsBot (Validated by Federico Sella)"
description: "GitLabのリモートコード実行脆弱性の実証コードが公開され、パッチ未適用のセルフマネージド18.11.3サーバーを標的としています。認証ユーザーはgitユーザーとしてコマンドを実行できます。"
original_url: "https://thehackernews.com/2026/07/researcher-publishes-gitlab-rce-poc.html"
source: "The Hacker News"
severity: "High"
target: "GitLab セルフマネージド 18.11.3"
cve: null
cvss: null
kev: null
tags: ["news", "cybersecurity"]
news-categories: ["cybersecurity"]
layout: "news"
draft: false
---

GitLabのリモートコード実行脆弱性の実証コードが公開され、パッチ未適用のセルフマネージド18.11.3サーバーを標的としています。認証ユーザーはgitユーザーとしてコマンドを実行できます。

{{< cyber-report severity="High" source="The Hacker News" target="GitLab セルフマネージド 18.11.3" >}}

2026年7月24日、depthfirstのセキュリティ研究者がGitLabのリモートコード実行脆弱性の実証コードを公開しました。この脆弱性は2026年6月10日にGitLabが修正したもので、プロジェクトへのプッシュアクセス権を持つ認証ユーザーが、アップデートを適用していないセルフマネージドGitLab 18.11.3サーバー上でgitユーザーとして任意のコマンドを実行できるものです。

{{< ad-banner >}}

このエクスプロイトは、プロジェクトにコミットされた巧妙に細工されたJupyterノートブックを利用します。攻撃者がコミット差分を開くと、悪意のあるノートブックがヒープリークを引き起こし、コマンド実行を可能にします。この手法は通常の認証制御をバイパスし、標準的なプロジェクトアクセス以外の特別な権限を必要としません。

セルフマネージドGitLabインスタンスを運用している組織は、6月10日のパッチを適用したことを直ちに確認すべきです。エクスプロイトコードが公開されたことで、特にインターネットに公開されているインスタンスでは、活発な悪用のリスクが高まります。ブルーチームは、異常なJupyterノートブックのコミットや予期しないgitユーザーアクティビティを監視する必要があります。

{{< netrunner-insight >}}

このエクスプロイトは、セルフマネージドCI/CDプラットフォームにおけるパッチ適用の遅延の危険性を浮き彫りにしています。SOCアナリストは、異常なgitユーザープロセスや予期しないJupyterノートブックのアップロードの検出を優先すべきです。DevSecOpsチームは、GitLabに対して厳格なパッチ適用ウィンドウを強制し、セルフマネージドインスタンスの露出を制限するためにネットワークセグメンテーションを検討する必要があります。

{{< /netrunner-insight >}}

---

**[完全な記事を The Hacker News で読む ›](https://thehackernews.com/2026/07/researcher-publishes-gitlab-rce-poc.html)**
