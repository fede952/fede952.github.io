---
title: "Siemens Teamcenterの脆弱性により可用性、完全性、機密性がリスクに"
date: "2026-05-16T08:47:33Z"
original_date: "2026-05-14T12:00:00"
lang: "ja"
translationKey: "siemens-teamcenter-flaws-risk-availability-integrity-confidentiality"
author: "NewsBot (Validated by Federico Sella)"
description: "Siemens Teamcenterの複数の脆弱性により、可用性、完全性、機密性が侵害される可能性があります。直ちに最新バージョンに更新してください。"
original_url: "https://www.cisa.gov/news-events/ics-advisories/icsa-26-134-04"
source: "CISA"
severity: "High"
target: "Siemens Teamcenter"
cve: "CVE-2024-4367"
cvss: 7.5
kev: null
tags: ["news", "cybersecurity"]
news-categories: ["cybersecurity"]
layout: "news"
draft: false
---

Siemens Teamcenterの複数の脆弱性により、可用性、完全性、機密性が侵害される可能性があります。直ちに最新バージョンに更新してください。

{{< cyber-report severity="High" source="CISA" target="Siemens Teamcenter" cve="CVE-2024-4367" cvss="7.5" >}}

Siemens Teamcenterには、可用性、完全性、機密性の侵害につながる可能性のある複数の脆弱性が存在します。これらの欠陥には、異常または例外的な状態の不適切なチェック、クロスサイトスクリプティング、ハードコードされた認証情報の使用が含まれます。影響を受けるバージョンはTeamcenter V2312、V2406、V2412、V2506、V2512です。

{{< ad-banner >}}

CVE-2024-4367は、PDF.jsでフォントを処理する際の型チェックの欠落であり、PDF.jsのコンテキストで任意のJavaScriptが実行される可能性があります。この脆弱性はFirefoxとThunderbirdに影響しますが、Siemensのアドバイザリに記載されています。Siemensは、これらのリスクを軽減するためにTeamcenterの最新バージョンに更新することを推奨しています。

これらの脆弱性のCVSS v3基本スコアは7.5で、深刻度が高いことを示しています。重要な製造業セクターが影響を受け、世界中に展開されています。組織はパッチ適用を優先し、これらの脆弱性への露出を確認する必要があります。

{{< netrunner-insight >}}

SOCアナリストは直ちにすべてのTeamcenterインスタンスを棚卸しし、最新バージョンへのパッチ適用を優先すべきです。DevSecOpsチームはPDF.jsコンポーネントが更新されていることを確認し、これらのCVEを狙った悪用試行を監視する必要があります。CVSSスコアが高く、完全な侵害の可能性があるため、これを優先度の高い是正措置として扱ってください。

{{< /netrunner-insight >}}

---

**[完全な記事を CISA で読む ›](https://www.cisa.gov/news-events/ics-advisories/icsa-26-134-04)**
