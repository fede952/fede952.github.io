---
title: "OpenSSLのHollowByte脆弱性、11バイトのTLSリクエストでメモリをフリーズ"
date: "2026-07-18T08:44:53Z"
original_date: "2026-07-17T20:20:53"
lang: "ja"
translationKey: "openssl-hollowbyte-flaw-freezes-memory-with-11-byte-tls-requests"
slug: "openssl-hollowbyte-flaw-freezes-memory-with-11-byte-tls-requests"
author: "NewsBot (Validated by Federico Sella)"
description: "OpenSSLのサービス拒否バグ「HollowByte」により、攻撃者は小さなTLSリクエストでサーバのメモリをフリーズさせることができます。OktaのRed Teamが報告し、CVEなしで修正がリリースされました。"
original_url: "https://thehackernews.com/2026/07/openssl-hollowbyte-flaw-could-freeze.html"
source: "The Hacker News"
severity: "High"
target: "glibcシステム上のOpenSSLサーバ"
cve: null
cvss: null
kev: null
tags: ["news", "cybersecurity"]
news-categories: ["cybersecurity"]
layout: "news"
draft: false
---

OpenSSLのサービス拒否バグ「HollowByte」により、攻撃者は小さなTLSリクエストでサーバのメモリをフリーズさせることができます。OktaのRed Teamが報告し、CVEなしで修正がリリースされました。

{{< cyber-report severity="High" source="The Hacker News" target="glibcシステム上のOpenSSLサーバ" >}}

新たに公開されたOpenSSLのサービス拒否脆弱性（OktaのRed TeamによりHollowByteと命名）により、攻撃者はわずか11バイトのTLSハンドシェイクデータでサーバのメモリを枯渇させることができます。この欠陥により、パッチ未適用のOpenSSLサーバは、決して到着しないメッセージに対して最大131KBのメモリを割り当て、glibcを使用するシステムでは、プロセスが再起動されるまでそのメモリは解放されません。

{{< ad-banner >}}

OpenSSLは2026年6月に、CVE識別子を割り当てず、アドバイザリを発行せず、チェンジログに変更を記載せずに修正をリリースしました。このバグを発見・報告したOktaのRed Teamは、修正がリリースされた後に詳細を公開しました。この脆弱性は、glibcベースのシステム上で動作するOpenSSLサーバに影響し、メモリ枯渇攻撃を受けやすくします。

攻撃には11バイトの単一のTLS ClientHelloのみが必要ですが、OpenSSLプロセスが長時間稼働し、多数の同時接続を処理する環境では影響が深刻になる可能性があります。glibc上でOpenSSLを実行している組織は、サービス拒否状態を防ぐために、2026年6月のアップデートを優先的に適用する必要があります。

{{< netrunner-insight >}}

これは、悪意のあるトラフィックが通常のTLSハンドシェイクに見えるため、従来のレート制限を回避する古典的なリソース枯渇ベクトルです。SOCアナリストはOpenSSLサーバのメモリ使用量の急増を監視し、DevSecOpsチームはCVEがなくても2026年6月のOpenSSLアップデートが適用されていることを確認する必要があります。CVEがないことは運用リスクを軽減しません。これを優先度の高いパッチとして扱ってください。

{{< /netrunner-insight >}}

---

**[完全な記事を The Hacker News で読む ›](https://thehackernews.com/2026/07/openssl-hollowbyte-flaw-could-freeze.html)**
