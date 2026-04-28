---
title: "CISA、Cisco Firepowerデバイスを標的とするFIRESTARTERバックドアを警告"
date: "2026-04-23T12:00:00"
lang: "ja"
translationKey: "cisa-warns-of-firestarter-backdoor-targeting-cisco-firepower-devices"
author: "NewsBot (Validated by Federico Sella)"
description: "CISAとNCSCが、APTアクターがCisco ASA/FTDデバイスで永続性を維持するためにFIRESTARTERバックドアを使用していることを警告。緊急対応手順が概説されています。"
original_url: "https://www.cisa.gov/news-events/analysis-reports/ar26-113a"
source: "CISA"
severity: "High"
target: "Cisco FirepowerおよびSecure Firewallデバイス"
cve: null
cvss: null
kev: null
tags: ["news", "cybersecurity"]
news-categories: ["cybersecurity"]
layout: "news"
draft: false
---

CISAとNCSCが、APTアクターがCisco ASA/FTDデバイスで永続性を維持するためにFIRESTARTERバックドアを使用していることを警告。緊急対応手順が概説されています。

{{< cyber-report severity="High" source="CISA" target="Cisco FirepowerおよびSecure Firewallデバイス" >}}

CISAと英国NCSCは、FIRESTARTERバックドアに関するマルウェア分析レポートを公開しました。このバックドアは、高度な持続的脅威（APT）アクターによって、ASAまたはFTDソフトウェアを実行する公開されたCisco FirepowerおよびSecure Firewallデバイスで永続性を維持するために使用されています。この分析はフォレンジック調査から得られたサンプルに基づいており、CISAはASAソフトウェアを実行するCisco Firepowerデバイスへの実際の埋め込みを確認しています。

{{< ad-banner >}}

この公開は、CISAの緊急指令25-03に沿ったもので、米国FCEB機関に対し、コアダンプを収集してCISAのMalware Next Generationプラットフォームに提出し、24時間体制の運用センターを通じて直ちに報告するよう求めています。組織は、CISAが次のステップを提供するまで追加の措置を取らないよう推奨されています。

このマルウェアはCisco FirepowerとSecure Firewallデバイスの両方に関連しますが、CISAはASAを実行するFirepowerデバイスでのみ埋め込みを確認しています。報告書は、警戒と侵害指標のプロアクティブなハンティングの必要性を強調しています。

{{< netrunner-insight >}}

SOCアナリストは、Cisco ASA/FTDデバイスからコアダンプを収集し、CISAに分析を提出することを優先すべきです。DevSecOpsチームは、Ciscoデバイスがベストプラクティスに従ってパッチ適用および構成されていることを確認し、異常な永続性メカニズムを監視する必要があります。このバックドアは、APTレベルの脅威に対してネットワークエッジデバイスを保護することの重要性を浮き彫りにしています。

{{< /netrunner-insight >}}

---

**[完全な記事を CISA で読む ›](https://www.cisa.gov/news-events/analysis-reports/ar26-113a)**
