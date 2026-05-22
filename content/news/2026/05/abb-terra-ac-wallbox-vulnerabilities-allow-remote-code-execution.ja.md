---
title: "ABB Terra AC Wallboxの脆弱性によりリモートコード実行が可能に"
date: "2026-05-22T10:24:17Z"
original_date: "2026-05-21T12:00:00"
lang: "ja"
translationKey: "abb-terra-ac-wallbox-vulnerabilities-allow-remote-code-execution"
author: "NewsBot (Validated by Federico Sella)"
description: "CISAは、ABB Terra AC Wallbox (JP) ≤1.8.33におけるヒープおよびスタックバッファオーバーフローを警告しています。CVE-2025-10504、CVE-2025-12142、CVE-2025-12143を緩和するには、バージョン1.8.36に更新してください。"
original_url: "https://www.cisa.gov/news-events/ics-advisories/icsa-26-141-05"
source: "CISA"
severity: "Medium"
target: "ABB Terra AC Wallbox (JP)"
cve: "CVE-2025-10504"
cvss: 6.1
kev: null
tags: ["news", "cybersecurity"]
news-categories: ["cybersecurity"]
layout: "news"
draft: false
---

CISAは、ABB Terra AC Wallbox (JP) ≤1.8.33におけるヒープおよびスタックバッファオーバーフローを警告しています。CVE-2025-10504、CVE-2025-12142、CVE-2025-12143を緩和するには、バージョン1.8.36に更新してください。

{{< cyber-report severity="Medium" source="CISA" target="ABB Terra AC Wallbox (JP)" cve="CVE-2025-10504" cvss="6.1" >}}

ABBは、Terra AC Wallbox (JP)製品ライン、特にバージョン1.8.33以前に影響する複数の脆弱性を開示しました。これらの欠陥には、ヒープベースのバッファオーバーフロー（CVE-2025-10504）、入力サイズを確認せずにバッファコピーを行う問題（CVE-2025-12142）、およびスタックベースのバッファオーバーフロー（CVE-2025-12143）が含まれます。悪用に成功すると、攻撃者がヒープメモリを破損させ、デバイスのリモート制御やフラッシュメモリへの不正書き込みを引き起こし、ファームウェアの動作を変更する可能性があります。

{{< ad-banner >}}

これらの脆弱性は、CVSS v3基本スコア6.1と評価され、中程度の深刻度を示しています。ABBはこれらの問題に対処するため、ファームウェアバージョン1.8.36をリリースしました。本製品はエネルギー分野で世界中に展開されており、ベンダーはできるだけ早くアップデートを適用することを推奨しています。

現在のところ活発な悪用は報告されていませんが、リモートコード実行やファームウェア改ざんの可能性があるため、これらの脆弱性はEV充電インフラの運用者にとって重要です。組織は、影響を受けるデバイス、特に信頼できないネットワークにさらされているデバイスのパッチ適用を優先すべきです。

{{< netrunner-insight >}}

SOCアナリストは、Terra AC Wallboxデバイスへの異常なトラフィック、特にフラッシュメモリへの予期しない書き込み操作を監視してください。DevSecOpsエンジニアは、充電器と通信するカスタムプロトコルにおいて厳格な入力検証を実施し、ファームウェアアップデートを迅速に適用するようにしてください。CVSSスコア6.1であることから、これらを中程度の優先度として扱いますが、重要なエネルギーインフラにおけるデバイスの役割を考慮すると、潜在的な影響は大きいです。

{{< /netrunner-insight >}}

---

**[完全な記事を CISA で読む ›](https://www.cisa.gov/news-events/ics-advisories/icsa-26-141-05)**
