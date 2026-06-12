---
title: "CISA、Naxclow IoTの重大な脆弱性によりデバイス乗っ取りの可能性を警告"
date: "2026-06-12T10:59:58Z"
original_date: "2026-06-11T12:00:00"
lang: "ja"
translationKey: "cisa-warns-of-critical-naxclow-iot-flaws-allowing-device-takeover"
author: "NewsBot (Validated by Federico Sella)"
description: "Naxclow IoTプラットフォームの複数の脆弱性（CVE-2026-42947を含む）により、デバイスのハイジャックや認証情報の収集が可能になります。スマートドアベルやホームハブに影響します。"
original_url: "https://www.cisa.gov/news-events/ics-advisories/icsa-26-162-02"
source: "CISA"
severity: "Critical"
target: "Naxclow IoTプラットフォームデバイス"
cve: "CVE-2026-42947"
cvss: 9.8
kev: null
tags: ["news", "cybersecurity"]
news-categories: ["cybersecurity"]
layout: "news"
draft: false
---

Naxclow IoTプラットフォームの複数の脆弱性（CVE-2026-42947を含む）により、デバイスのハイジャックや認証情報の収集が可能になります。スマートドアベルやホームハブに影響します。

{{< cyber-report severity="Critical" source="CISA" target="Naxclow IoTプラットフォームデバイス" cve="CVE-2026-42947" cvss="9.8" >}}

CISAは勧告（ICSA-26-162-02）を発行し、Naxclow IoTプラットフォームの複数の脆弱性について詳細を明らかにしました。影響を受ける製品には、Smart Doorbell X3、X Smart Home、V720、ix camなどが含まれます。最も深刻な脆弱性であるCVE-2026-42947はCVSSスコア9.8であり、ユーザー制御のキーによる認証バイパスが関与しており、攻撃者がconfirm-then-bindシーケンスをリプレイして、ユーザーの操作なしにデバイスを任意のアカウントに静かに再割り当てできるようになります。

{{< ad-banner >}}

追加の弱点には、認証チェックの欠如、ハードコードされた暗号鍵の使用、予測可能な識別子の生成、外部からアクセス可能なファイルへの機密情報の挿入が含まれます。悪用に成功すると、デバイスのなりすまし、通信の傍受や操作、大規模な認証情報の収集、影響を受けるシステムへの不正アクセスが可能になる可能性があります。

これらの脆弱性は、リストされた製品のすべてのバージョンに影響し、デバイスは世界中の商業施設に展開されています。中国に本社を置くNaxclowはまだパッチをリリースしていません。これらのデバイスを使用している組織は、直ちにネットワークセグメンテーションと監視を実施して、異常なデバイスバインディングアクティビティを検出する必要があります。

{{< netrunner-insight >}}

これは教科書的なサプライチェーンIoTの悪夢です。ハードコードされた鍵、予測可能なID、リプレイ可能なオンボーディングフロー。SOCチームはログで予期しないデバイス再割り当てを探し、パッチが到着するまでNaxclowデバイスを別のVLANに隔離することを検討すべきです。DevSecOpsはIoTオンボーディングにおいて暗号化デバイスIDと相互認証を推進しなければなりません。

{{< /netrunner-insight >}}

---

**[完全な記事を CISA で読む ›](https://www.cisa.gov/news-events/ics-advisories/icsa-26-162-02)**
