---
title: "Windows BitLockerのゼロデイバイパスPoC公開：YellowKeyとGreenPlasma"
date: "2026-05-14T09:30:15Z"
original_date: "2026-05-13T16:37:49"
lang: "ja"
translationKey: "windows-bitlocker-zero-day-bypass-poc-released-yellowkey-and-greenplasma"
author: "NewsBot (Validated by Federico Sella)"
description: "2つの未パッチのWindows脆弱性—YellowKey（BitLockerバイパス）とGreenPlasma（権限昇格）—の概念実証エクスプロイトが公開され、暗号化ドライブにリスクをもたらしています。"
original_url: "https://www.bleepingcomputer.com/news/security/windows-bitlocker-zero-day-gives-access-to-protected-drives-poc-released/"
source: "BleepingComputer"
severity: "High"
target: "Windows BitLockerで保護されたドライブ"
cve: null
cvss: null
kev: null
tags: ["news", "cybersecurity"]
news-categories: ["cybersecurity"]
layout: "news"
draft: false
---

2つの未パッチのWindows脆弱性—YellowKey（BitLockerバイパス）とGreenPlasma（権限昇格）—の概念実証エクスプロイトが公開され、暗号化ドライブにリスクをもたらしています。

{{< cyber-report severity="High" source="BleepingComputer" target="Windows BitLockerで保護されたドライブ" >}}

サイバーセキュリティ研究者が、YellowKeyおよびGreenPlasmaと呼ばれる2つの未パッチのMicrosoft Windows脆弱性に対する概念実証（PoC）エクスプロイトを公開しました。YellowKeyは、適切な認証なしに保護されたドライブ上のデータにアクセスできるBitLockerバイパスであり、GreenPlasmaは、侵害されたシステム上で攻撃者が昇格した権限を取得できる権限昇格の欠陥です。

{{< ad-banner >}}

これらのPoCの公開により、脅威アクターが手法を悪用できるようになり、エクスプロイトのリスクが高まります。BitLockerをフルディスク暗号化に依存している組織は、自社の露出を評価し、TPM+PIN保護の有効化やプリブート認証の使用などの追加のセキュリティ制御を検討する必要があります。

Microsoftはこれらの脆弱性に対するパッチをまだリリースしておらず、修正が展開されるまでシステムは露出したままです。セキュリティチームは、暗号化ドライブへの異常なアクセスパターンを監視し、不要なブートオプションの無効化や強力なPINポリシーの適用など、可能な限り回避策を適用する必要があります。

{{< netrunner-insight >}}

SOCアナリストは、BitLockerで保護されたドライブへの不正アクセス試行や権限昇格イベントの監視を優先してください。DevSecOpsエンジニアは、公開されたPoCに対して自社環境をテストし、脆弱な構成を特定し、セキュアブートや測定ブートログなどの補完的制御を実装する必要があります。

{{< /netrunner-insight >}}

---

**[完全な記事を BleepingComputer で読む ›](https://www.bleepingcomputer.com/news/security/windows-bitlocker-zero-day-gives-access-to-protected-drives-poc-released/)**
