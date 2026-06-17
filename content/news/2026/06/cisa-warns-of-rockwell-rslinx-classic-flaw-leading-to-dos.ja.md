---
title: "CISA、Rockwell RSLinx ClassicのDoS脆弱性を警告"
date: "2026-06-17T11:42:55Z"
original_date: "2026-06-16T12:00:00"
lang: "ja"
translationKey: "cisa-warns-of-rockwell-rslinx-classic-flaw-leading-to-dos"
author: "NewsBot (Validated by Federico Sella)"
description: "CISA勧告は、Rockwell Automation RSLinx Classic ≤4.50.00におけるスタックベースのバッファオーバーフロー（CVE-2020-13573）を強調し、サービス拒否やリモートコード実行のリスクがあるとしています。"
original_url: "https://www.cisa.gov/news-events/ics-advisories/icsa-26-167-02"
source: "CISA"
severity: "High"
target: "Rockwell Automation RSLinx Classic"
cve: "CVE-2020-13573"
cvss: 7.5
kev: null
tags: ["news", "cybersecurity"]
news-categories: ["cybersecurity"]
layout: "news"
draft: false
---

CISA勧告は、Rockwell Automation RSLinx Classic ≤4.50.00におけるスタックベースのバッファオーバーフロー（CVE-2020-13573）を強調し、サービス拒否やリモートコード実行のリスクがあるとしています。

{{< cyber-report severity="High" source="CISA" target="Rockwell Automation RSLinx Classic" cve="CVE-2020-13573" cvss="7.5" >}}

CISAは、広く使用されている産業用通信ソフトウェアであるRockwell Automation RSLinx Classicの脆弱性に関する勧告（ICSA-26-167-02）を発表しました。CVE-2020-13573として識別されるこの欠陥は、スタックベースのバッファオーバーフローであり、リモートから悪用されて任意のコードを実行したり、サービス拒否を引き起こしたりする可能性があり、アプリケーションが応答しなくなり、自動的に回復できなくなります。

{{< ad-banner >}}

影響を受けるバージョンは、RSLinx Classic バージョン4.50.00までを含みます。この脆弱性のCVSS v3スコアは7.5で、深刻度が高いことを示しています。Rockwell Automationは、バージョン4.60.00以降へのアップグレード、または直ちにアップグレードできない顧客向けにパッチBF31213の適用を推奨しています。また、勧告では根本的な弱点としてCWE-125（境界外読み取り）が参照されています。

関与する重要インフラセクター（重要製造、エネルギー、食品・農業、上下水道）と製品のグローバルな展開を考慮すると、タイムリーなパッチ適用が不可欠です。組織は、特にRSLinx Classicが信頼できないネットワークに公開されている環境では、悪用のリスクを軽減するためにこのアップデートを優先すべきです。

{{< netrunner-insight >}}

SOCアナリストは、RSLinx Classicプロセスでの異常なクラッシュや応答不能を監視してください。これらは悪用の試みを示している可能性があります。DevSecOpsチームは、直ちにバージョン4.60.00へのアップグレードまたはパッチBF31213の適用を計画し、RSLinxインスタンスがインターネットから直接アクセスできないようにしてください。CVSSスコアとリモートコード実行の可能性を考慮し、これを優先度の高い是正項目として扱ってください。

{{< /netrunner-insight >}}

---

**[完全な記事を CISA で読む ›](https://www.cisa.gov/news-events/ics-advisories/icsa-26-167-02)**
