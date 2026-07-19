---
title: "7-Zip 26.02、悪意のあるアーカイブ内のRCE脆弱性を修正"
date: "2026-07-19T09:02:18Z"
original_date: "2026-07-18T19:32:02"
lang: "ja"
translationKey: "7-zip-26-02-patches-rce-flaw-in-malicious-archives"
slug: "7-zip-26-02-patches-rce-flaw-in-malicious-archives"
author: "NewsBot (Validated by Federico Sella)"
description: "7-Zipは、特別に細工された圧縮ファイルを開くことでトリガーされるリモートコード実行の脆弱性を修正するバージョン26.02をリリースしました。直ちに更新してください。"
original_url: "https://www.bleepingcomputer.com/news/security/update-now-7-zip-fixes-rce-flaw-exploitable-with-malicious-archives/"
source: "BleepingComputer"
severity: "High"
target: "7-Zipユーザー"
cve: null
cvss: null
kev: null
tags: ["news", "cybersecurity"]
news-categories: ["cybersecurity"]
layout: "news"
draft: false
---

7-Zipは、特別に細工された圧縮ファイルを開くことでトリガーされるリモートコード実行の脆弱性を修正するバージョン26.02をリリースしました。直ちに更新してください。

{{< cyber-report severity="High" source="BleepingComputer" target="7-Zipユーザー" >}}

7-Zipバージョン26.02がリリースされ、攻撃者が被害者のシステム上で任意のコードを実行できる可能性があるリモートコード実行（RCE）脆弱性に対処しました。この欠陥は、ユーザーに悪意のあるペイロードを含むアーカイブなどの特別に細工された圧縮ファイルを開かせることで悪用可能です。

{{< ad-banner >}}

この脆弱性は、人気のファイルアーカイバの以前のすべてのバージョンに影響します。発表ではCVE識別子は開示されていませんが、システム全体が侵害される可能性があるため、深刻度は高いと見なされています。ユーザーは直ちに最新バージョンに更新することを強く推奨します。

7-Zipがエンタープライズ環境とコンシューマ環境の両方で広く使用されていることを考えると、このパッチは攻撃対象領域を減らすために重要です。組織は、自動更新メカニズムまたは手動インストールを介した展開を優先すべきです。

{{< netrunner-insight >}}

SOCアナリストは、異常なアーカイブファイルのアクティビティを監視し、すべてのエンドポイントで7-Zipが更新されていることを確認する必要があります。DevSecOpsチームは、このアップデートをパッチ管理パイプラインに統合し、古いバージョンの7-Zipが機密システムにアクセスするのをブロックすることを検討すべきです。

{{< /netrunner-insight >}}

---

**[完全な記事を BleepingComputer で読む ›](https://www.bleepingcomputer.com/news/security/update-now-7-zip-fixes-rce-flaw-exploitable-with-malicious-archives/)**
