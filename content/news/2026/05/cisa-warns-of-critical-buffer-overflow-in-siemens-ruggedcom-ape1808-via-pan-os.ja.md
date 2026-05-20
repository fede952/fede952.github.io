---
title: "CISA、Siemens RUGGEDCOM APE1808におけるPAN-OS経由の重大なバッファオーバーフローを警告"
date: "2026-05-20T10:21:56Z"
original_date: "2026-05-19T12:00:00"
lang: "ja"
translationKey: "cisa-warns-of-critical-buffer-overflow-in-siemens-ruggedcom-ape1808-via-pan-os"
author: "NewsBot (Validated by Federico Sella)"
description: "Palo Alto Networks PAN-OS Captive PortalのバッファオーバーフローがSiemens RUGGEDCOM APE1808デバイスに影響。CVE-2026-0300により、認証されていないリモートからの攻撃者がルート権限でコードを実行可能。"
original_url: "https://www.cisa.gov/news-events/ics-advisories/icsa-26-139-02"
source: "CISA"
severity: "Critical"
target: "Siemens RUGGEDCOM APE1808デバイス"
cve: "CVE-2026-0300"
cvss: 10.0
kev: null
tags: ["news", "cybersecurity"]
news-categories: ["cybersecurity"]
layout: "news"
draft: false
---

Palo Alto Networks PAN-OS Captive PortalのバッファオーバーフローがSiemens RUGGEDCOM APE1808デバイスに影響。CVE-2026-0300により、認証されていないリモートからの攻撃者がルート権限でコードを実行可能。

{{< cyber-report severity="Critical" source="CISA" target="Siemens RUGGEDCOM APE1808デバイス" cve="CVE-2026-0300" cvss="10.0" >}}

CISAは、Palo Alto Networks PAN-OSソフトウェアのUser-ID認証ポータル（Captive Portal）サービスにおける重大なバッファオーバーフローの脆弱性に関する勧告（ICSA-26-139-02）を公開しました。この欠陥はCVE-2026-0300として追跡され、CVSSスコアは10.0で、認証されていない攻撃者が特別に細工したパケットを送信することで、PAシリーズおよびVMシリーズのファイアウォール上でルート権限で任意のコードを実行できるようになります。

{{< ad-banner >}}

この脆弱性は、すべてのバージョンのSiemens RUGGEDCOM APE1808デバイスに影響します。Siemensは修正バージョンを準備中であり、Palo Alto Networksの上流セキュリティ通知で提供されている回避策を実施することを推奨しています。パッチが利用可能になるまで、組織はCaptive Portalサービスが不要な場合は無効にし、影響を受けるデバイスへのネットワークアクセスを制限する必要があります。

重大なCVSSスコアとシステム全体の完全な侵害の可能性を考慮すると、即時の対応が必要です。この勧告は重要製造業セクターを対象としており、デバイスは世界中に展開されています。運用者は、緩和策の適用を優先し、悪用の兆候がないか監視する必要があります。

{{< netrunner-insight >}}

これはサプライチェーンリスクの典型的な例です。サードパーティコンポーネント（PAN-OS）が産業用製品に重大な欠陥をもたらしています。SOCアナリストは、Captive Portalポートへの異常なトラフィックを即座に調査し、セグメンテーションによって露出を制限する必要があります。DevSecOpsチームは、RUGGEDCOM APE1808の全インスタンスを棚卸しし、上流のPalo Alto Networksの緩和策を遅滞なく適用しなければなりません。

{{< /netrunner-insight >}}

---

**[完全な記事を CISA で読む ›](https://www.cisa.gov/news-events/ics-advisories/icsa-26-139-02)**
