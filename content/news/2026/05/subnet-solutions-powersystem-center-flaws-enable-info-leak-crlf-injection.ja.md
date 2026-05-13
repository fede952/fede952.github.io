---
title: "Subnet Solutions PowerSYSTEM Centerの脆弱性により情報漏洩とCRLFインジェクションが可能に"
date: "2026-05-13T09:40:06Z"
original_date: "2026-05-12T12:00:00"
lang: "ja"
translationKey: "subnet-solutions-powersystem-center-flaws-enable-info-leak-crlf-injection"
author: "NewsBot (Validated by Federico Sella)"
description: "CISAは、Subnet Solutions PowerSYSTEM Centerの複数の脆弱性（情報漏洩やCRLFインジェクションを含む）について警告しています。影響を受けるバージョンは2020年から2026年までです。"
original_url: "https://www.cisa.gov/news-events/ics-advisories/icsa-26-132-02"
source: "CISA"
severity: "High"
target: "Subnet Solutions PowerSYSTEM Center"
cve: "CVE-2026-35504"
cvss: 8.2
kev: null
tags: ["news", "cybersecurity"]
news-categories: ["cybersecurity"]
layout: "news"
draft: false
---

CISAは、Subnet Solutions PowerSYSTEM Centerの複数の脆弱性（情報漏洩やCRLFインジェクションを含む）について警告しています。影響を受けるバージョンは2020年から2026年までです。

{{< cyber-report severity="High" source="CISA" target="Subnet Solutions PowerSYSTEM Center" cve="CVE-2026-35504" cvss="8.2" >}}

CISAは、重要製造業やエネルギー分野で使用されるプラットフォームであるSubnet Solutions PowerSYSTEM Centerの複数の脆弱性を詳細に記した勧告（ICSA-26-132-02）を発表しました。これらの欠陥には、認証されたユーザーが限られた権限でデバイスアカウントをエクスポートし、通常は管理者に制限されている機密情報を公開できる不適切な認可（CVE-2026-26289）が含まれます。さらに、CRLFインジェクションの脆弱性（CVE-2026-35504、CVE-2026-33570、CVE-2026-35555）により、攻撃者が悪意のあるヘッダーやレスポンスを注入できる可能性があります。

{{< ad-banner >}}

影響を受けるバージョンは、PowerSYSTEM Center 2020（5.8.x～5.28.x）、2024（6.0.x～6.1.x）、2026（7.0.x）に及びます。これらの脆弱性のCVSS v3基本スコアは8.2で、深刻度が高いことを示しています。悪用に成功すると、情報漏洩やセッション操作、HTTPレスポンス分割の可能性が生じます。

この製品が世界中の重要インフラで展開されていることを考慮し、組織はパッチ適用を優先すべきです。Subnet Solutionsはアップデートをリリースしている可能性があります。管理者はベンダーのセキュリティ勧告を参照し、最新のパッチを適用することを推奨します。それまでの間、PowerSYSTEM Centerへのネットワークアクセスを制限し、異常な活動を監視してください。

{{< netrunner-insight >}}

SOCアナリストは、認証ログで異常なデバイスアカウントのエクスポートを監視してください。これはCVE-2026-26289の悪用の兆候です。DevSecOpsチームは直ちにPowerSYSTEM Centerのバージョンをインベントリし、パッチを適用してください。CRLFインジェクションベクトル（CVE-2026-35504など）は他の攻撃と連鎖してセッションの整合性を損なう可能性があります。CVSS 8.2のスコアと重要セクターでの露出を考慮し、これを優先度の高い是正として扱ってください。

{{< /netrunner-insight >}}

---

**[完全な記事を CISA で読む ›](https://www.cisa.gov/news-events/ics-advisories/icsa-26-132-02)**
