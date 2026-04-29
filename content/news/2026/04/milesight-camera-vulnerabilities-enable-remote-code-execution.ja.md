---
title: "Milesightカメラの脆弱性によりリモートコード実行が可能に"
date: "2026-04-29T07:21:59Z"
original_date: "2026-04-23T12:00:00"
lang: "ja"
translationKey: "milesight-camera-vulnerabilities-enable-remote-code-execution"
author: "NewsBot (Validated by Federico Sella)"
description: "CISAは、複数のMilesightカメラモデルに影響する重大な脆弱性（CVE-2026-28747など）がデバイスのクラッシュやリモートコード実行につながる可能性があると警告しています。"
original_url: "https://www.cisa.gov/news-events/ics-advisories/icsa-26-113-03"
source: "CISA"
severity: "Critical"
target: "Milesight IP Cameras"
cve: "CVE-2026-28747"
cvss: null
kev: null
tags: ["news", "cybersecurity"]
news-categories: ["cybersecurity"]
layout: "news"
draft: false
---

CISAは、複数のMilesightカメラモデルに影響する重大な脆弱性（CVE-2026-28747など）がデバイスのクラッシュやリモートコード実行につながる可能性があると警告しています。

{{< cyber-report severity="Critical" source="CISA" target="Milesight IP Cameras" cve="CVE-2026-28747" >}}

CISAは、広範囲のMilesightカメラモデルに影響する複数の脆弱性を詳細に説明した勧告（ICSA-26-113-03）を発表しました。CVE-2026-28747、CVE-2026-27785、CVE-2026-32644、CVE-2026-32649、CVE-2026-20766として特定されたこれらの欠陥は、MS-Cxx63-PD、MS-Cxx64-xPDなどの複数の製品ラインにわたるファームウェアバージョンに影響します。悪用に成功すると、攻撃者はデバイスをクラッシュさせたり、リモートコード実行を達成したりする可能性があります。

{{< ad-banner >}}

影響を受けるモデルは複数のシリーズにわたり、ファームウェアバージョンは51.7.0.77-r12、3x.8.0.3-r11、63.8.0.4-r3などです。リモートコード実行の重大性を考慮すると、これらの脆弱性は監視やIoT展開でMilesightカメラを使用する組織に大きなリスクをもたらします。CISAは、利用可能なパッチを適用し、ベンダーのガイダンスに従って露出を軽減することを推奨しています。

勧告ではCVSSスコアや活発な悪用の証拠は提供されていませんが、デバイス侵害やネットワーク侵入の可能性は直ちに対処する必要があります。セキュリティチームは影響を受けるカメラモデルを特定し、IoTデバイスを重要なネットワークから分離し、ファームウェアの更新を優先する必要があります。

{{< netrunner-insight >}}

SOCアナリストは、カメラサブネットからの異常なトラフィックを監視し、これらのデバイスが分離されていることを確認してください。DevSecOpsエンジニアは、すべてのMilesightカメラのパッチ適用を迅速化すべきです。エッジデバイスにおけるリモートコード実行の脆弱性は、しばしば横方向の移動のエントリポイントとなるからです。ベンダーのパッチが確認されるまで、これらのCVEを重大として扱ってください。

{{< /netrunner-insight >}}

---

**[完全な記事を CISA で読む ›](https://www.cisa.gov/news-events/ics-advisories/icsa-26-113-03)**
