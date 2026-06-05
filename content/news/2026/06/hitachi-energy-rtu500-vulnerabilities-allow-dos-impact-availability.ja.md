---
title: "日立エナジーRTU500の脆弱性によりDoSが可能、可用性に影響"
date: "2026-06-05T10:46:09Z"
original_date: "2026-06-04T12:00:00"
lang: "ja"
translationKey: "hitachi-energy-rtu500-vulnerabilities-allow-dos-impact-availability"
author: "NewsBot (Validated by Federico Sella)"
description: "CISAは日立エナジーRTU500シリーズの複数の脆弱性（NULLポインタ参照や無限ループなど、CVSS 7.8）を警告。影響を受けるバージョンがリスト化。"
original_url: "https://www.cisa.gov/news-events/ics-advisories/icsa-26-155-04"
source: "CISA"
severity: "High"
target: "日立エナジーRTU500シリーズ CMUファームウェア"
cve: "CVE-2025-69421"
cvss: 7.8
kev: null
tags: ["news", "cybersecurity"]
news-categories: ["cybersecurity"]
layout: "news"
draft: false
---

CISAは日立エナジーRTU500シリーズの複数の脆弱性（NULLポインタ参照や無限ループなど、CVSS 7.8）を警告。影響を受けるバージョンがリスト化。

{{< cyber-report severity="High" source="CISA" target="日立エナジーRTU500シリーズ CMUファームウェア" cve="CVE-2025-69421" cvss="7.8" >}}

日立エナジーは、RTU500シリーズCMUファームウェアに影響する複数の脆弱性を開示しました。これらの欠陥には、NULLポインタ参照、整数オーバーフローまたはラップアラウンド、および到達不能な終了条件を伴うループ（無限ループ）が含まれ、サービス拒否状態を引き起こす可能性があります。悪用は主に製品の可用性に影響し、機密性と完全性に二次的な影響を及ぼす可能性があります。

{{< ad-banner >}}

CISA（ICSA-26-155-04）によって公開された勧告では、影響を受けるファームウェアバージョンが12.7.1から13.8.1までリストされています。関連するCVEには、CVE-2025-69421、CVE-2026-24515、CVE-2026-25210、CVE-2026-32776、CVE-2026-32777、CVE-2026-32778、CVE-2026-8479が含まれます。これらの脆弱性のCVSS v3基本スコアは7.8で、高い深刻度を示しています。

日立エナジーは、勧告の修復ガイダンスに従って即時対応を推奨しています。重要なインフラストラクチャの状況を考慮すると、影響を受けるRTU500バージョンを使用している組織はパッチを優先し、悪用リスクを軽減するためにネットワークセグメンテーションを実装する必要があります。

{{< netrunner-insight >}}

これらの脆弱性は、OTデバイスがパッチサイクルで遅れをとることが多いことを思い出させます。SOCチームはRTU500ユニットへの異常なトラフィックを監視し、これらのデバイスが信頼できないネットワークから隔離されていることを確認する必要があります。DevSecOpsエンジニアは、展開前に既知のCVEを検出するために、CI/CDパイプラインにファームウェアスキャンを統合する必要があります。

{{< /netrunner-insight >}}

---

**[完全な記事を CISA で読む ›](https://www.cisa.gov/news-events/ics-advisories/icsa-26-155-04)**
