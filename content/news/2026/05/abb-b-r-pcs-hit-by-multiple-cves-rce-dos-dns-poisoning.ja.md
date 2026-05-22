---
title: "ABB B&R PCが複数のCVEに影響：RCE、DoS、DNSポイズニング"
date: "2026-05-22T10:21:58Z"
original_date: "2026-05-21T12:00:00"
lang: "ja"
translationKey: "abb-b-r-pcs-hit-by-multiple-cves-rce-dos-dns-poisoning"
author: "NewsBot (Validated by Federico Sella)"
description: "CISAがABB B&R産業用PCの脆弱性を警告。アップデートが利用可能。攻撃者はリモートコード実行、DoS、DNSキャッシュポイズニング、データ漏洩を引き起こす可能性がある。"
original_url: "https://www.cisa.gov/news-events/ics-advisories/icsa-26-141-02"
source: "CISA"
severity: "High"
target: "ABB B&R産業用PC"
cve: "CVE-2023-45229"
cvss: null
kev: null
tags: ["news", "cybersecurity"]
news-categories: ["cybersecurity"]
layout: "news"
draft: false
---

CISAがABB B&R産業用PCの脆弱性を警告。アップデートが利用可能。攻撃者はリモートコード実行、DoS、DNSキャッシュポイズニング、データ漏洩を引き起こす可能性がある。

{{< cyber-report severity="High" source="CISA" target="ABB B&R産業用PC" cve="CVE-2023-45229" >}}

ABBは、APC4100、APC910、C80、MPC3100、PPC1200、PPC900、APC2200を含む複数のB&R産業用PC製品ラインに影響する脆弱性を開示した。CVE-2023-45229からCVE-2023-45237として追跡されるこれらの欠陥により、ネットワークベースの攻撃者がリモートコードを実行し、サービス拒否攻撃を仕掛け、DNSキャッシュを汚染し、機密情報を抽出することが可能になる。

{{< ad-banner >}}

アドバイザリには各製品の影響を受けるバージョンが記載されており、問題を修正するためのアップデートが利用可能である。例えば、APC4100のバージョン1.09未満は脆弱であり、バージョン1.09は修正済みである。同様に、APC910のバージョン1.25以下が影響を受ける。ABBは直ちに最新のファームウェアバージョンにアップグレードすることを推奨している。

産業用制御システム（ICS）の状況を考慮すると、これらの脆弱性は運用技術環境に重大なリスクをもたらす。影響を受けるABB B&R PCを使用している組織は、特にデバイスが信頼できないネットワークにさらされている場合、パッチ適用を優先すべきである。

{{< netrunner-insight >}}

SOCアナリストは、B&R PCからの異常なDNSクエリや予期しない接続についてネットワークトラフィックを監視する。DevSecOpsチームは影響を受けるすべてのデバイスをインベントリし、これらのCVEは認証なしでリモートコード実行を可能にするため、できるだけ早くファームウェアアップデートを適用する。ICSネットワークをセグメント化して露出を制限することを検討する。

{{< /netrunner-insight >}}

---

**[完全な記事を CISA で読む ›](https://www.cisa.gov/news-events/ics-advisories/icsa-26-141-02)**
