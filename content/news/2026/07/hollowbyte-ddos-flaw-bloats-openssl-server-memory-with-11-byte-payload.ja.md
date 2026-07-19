---
title: "HollowByte DDoS脆弱性、11バイトのペイロードでOpenSSLサーバーのメモリを膨張させる"
date: "2026-07-19T09:04:58Z"
original_date: "2026-07-17T17:56:21"
lang: "ja"
translationKey: "hollowbyte-ddos-flaw-bloats-openssl-server-memory-with-11-byte-payload"
slug: "hollowbyte-ddos-flaw-bloats-openssl-server-memory-with-11-byte-payload"
author: "NewsBot (Validated by Federico Sella)"
description: "HollowByteと名付けられた脆弱性により、認証されていない攻撃者がわずか11バイトの悪意あるペイロードでOpenSSLサーバーにサービス拒否状態を引き起こすことができます。"
original_url: "https://www.bleepingcomputer.com/news/security/hollowbyte-ddos-flaw-bloats-openssl-server-memory-with-11-byte-payload/"
source: "BleepingComputer"
severity: "High"
target: "OpenSSLサーバー"
cve: null
cvss: null
kev: null
tags: ["news", "cybersecurity"]
news-categories: ["cybersecurity"]
layout: "news"
draft: false
---

HollowByteと名付けられた脆弱性により、認証されていない攻撃者がわずか11バイトの悪意あるペイロードでOpenSSLサーバーにサービス拒否状態を引き起こすことができます。

{{< cyber-report severity="High" source="BleepingComputer" target="OpenSSLサーバー" >}}

新たに発見されたHollowByteという脆弱性により、認証されていない攻撃者がわずか11バイトの特別に細工されたペイロードを送信することで、OpenSSLサーバーにサービス拒否（DoS）状態を引き起こすことができます。この欠陥はメモリ割り当ての非効率性を悪用し、サーバーのメモリを膨張させ、最終的に利用可能なリソースを枯渇させます。

{{< ad-banner >}}

この攻撃は認証を必要とせず、リモートから実行可能であるため、安全な通信をOpenSSLに依存する組織にとって重大な脅威となります。ペイロードサイズが最小限であるため、攻撃者は限られた帯域幅で影響を増幅し、最小限の労力でサーバーを圧倒する可能性があります。

まだCVE識別子は割り当てられていませんが、この脆弱性はOpenSSLプロジェクトに開示されており、パッチが期待されています。それまでの間、管理者はメモリ使用量を監視し、レート制限や侵入検知ルールを実装して潜在的な悪用を軽減することが推奨されます。

{{< netrunner-insight >}}

SOCアナリストにとって、これは従来の帯域幅ベースの防御を回避できる、低帯域幅で高インパクトな古典的なDoSベクトルです。DevSecOpsチームは、パッチが利用可能になり次第優先的に適用し、異常なメモリ増加を検出するためのメモリ監視アラートの導入を検討すべきです。11バイトのペイロードは、脅威検知ルールに含める理想的な候補です。

{{< /netrunner-insight >}}

---

**[完全な記事を BleepingComputer で読む ›](https://www.bleepingcomputer.com/news/security/hollowbyte-ddos-flaw-bloats-openssl-server-memory-with-11-byte-payload/)**
