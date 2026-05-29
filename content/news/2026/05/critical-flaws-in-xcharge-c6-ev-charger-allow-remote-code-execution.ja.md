---
title: "XCharge C6 EV充電器の重大な脆弱性によりリモートコード実行が可能に"
date: "2026-05-29T10:39:44Z"
original_date: "2026-05-28T12:00:00"
lang: "ja"
translationKey: "critical-flaws-in-xcharge-c6-ev-charger-allow-remote-code-execution"
author: "NewsBot (Validated by Federico Sella)"
description: "CISAは、XCharge C6 EV充電コントローラにおける認証不要の脆弱性（CVE-2026-9037、CVSSスコア9.8）について警告しています。"
original_url: "https://www.cisa.gov/news-events/ics-advisories/icsa-26-148-08"
source: "CISA"
severity: "Critical"
target: "XCharge C6 EV充電コントローラ"
cve: "CVE-2026-9037"
cvss: 9.8
kev: null
tags: ["news", "cybersecurity"]
news-categories: ["cybersecurity"]
layout: "news"
draft: false
---

CISAは、XCharge C6 EV充電コントローラにおける認証不要の脆弱性（CVE-2026-9037、CVSSスコア9.8）について警告しています。

{{< cyber-report severity="Critical" source="CISA" target="XCharge C6 EV充電コントローラ" cve="CVE-2026-9037" cvss="9.8" >}}

CISAは、XCharge C6電気自動車充電コントローラにおける複数の重大な脆弱性を詳細に説明した勧告（ICSA-26-148-08）を公開しました。これらの脆弱性には、整合性チェックなしのコードダウンロード（CWE-494）、スタックベースのバッファオーバーフロー、および安全でないデフォルトによるリソースの初期化が含まれます。悪用に成功すると、攻撃者はデバイス上で管理者権限を取得したり、任意のコードを実行したりする可能性があります。

{{< ad-banner >}}

最も深刻な脆弱性であるCVE-2026-9037は、ファームウェアパッケージの信頼性を検証できないファームウェア更新メカニズムに関係しています。暗号署名の検証がないため、管理チャネルに干渉したりなりすましたりできる攻撃者が、不正なファームウェアをインストールし、高権限でのコード実行につながる可能性があります。この脆弱性のCVSS v3スコアは9.8で、重大な深刻度を示しています。

XChargeは、2026年5月22日時点で、影響を受けるすべての充電器向けのファームウェアアップデートを展開しています。ユーザーはデバイスが更新されていることを確認し、必要に応じてXChargeサポートに連絡することをお勧めします。影響を受ける製品は、複数の国の交通システム分野で広く展開されています。

{{< netrunner-insight >}}

SOCアナリストは、XCharge C6充電器の管理インターフェースに対する不正アクセスや異常なファームウェア更新要求の監視を優先してください。DevSecOpsチームは、ネットワークセグメンテーションを実施し、ベンダーのパッチを直ちに適用する必要があります。整合性チェックの欠如により、これらのデバイスはサプライチェーン攻撃の格好の標的となっています。

{{< /netrunner-insight >}}

---

**[完全な記事を CISA で読む ›](https://www.cisa.gov/news-events/ics-advisories/icsa-26-148-08)**
