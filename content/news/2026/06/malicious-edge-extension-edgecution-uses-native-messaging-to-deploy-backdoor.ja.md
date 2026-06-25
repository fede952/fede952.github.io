---
title: "悪意あるEdge拡張機能「Edgecution」がNative Messagingを悪用してバックドアを展開"
date: "2026-06-25T10:16:09Z"
original_date: "2026-06-24T20:58:22"
lang: "ja"
translationKey: "malicious-edge-extension-edgecution-uses-native-messaging-to-deploy-backdoor"
author: "NewsBot (Validated by Federico Sella)"
description: "「Edgecution」と名付けられた悪意あるMicrosoft Edge拡張機能が、Native Messagingを介してブラウザのサンドボックスを脱出し、ランサムウェア攻撃でPythonベースのバックドアを展開します。"
original_url: "https://www.bleepingcomputer.com/news/security/malicious-edge-extension-abuses-native-messaging-as-bridge-to-malware/"
source: "BleepingComputer"
severity: "High"
target: "Microsoft Edgeユーザー"
cve: null
cvss: null
kev: null
tags: ["news", "cybersecurity"]
news-categories: ["cybersecurity"]
layout: "news"
draft: false
---

「Edgecution」と名付けられた悪意あるMicrosoft Edge拡張機能が、Native Messagingを介してブラウザのサンドボックスを脱出し、ランサムウェア攻撃でPythonベースのバックドアを展開します。

{{< cyber-report severity="High" source="BleepingComputer" target="Microsoft Edgeユーザー" >}}

「Edgecution」と呼ばれる悪意あるMicrosoft Edge拡張機能がランサムウェア攻撃で確認され、ブラウザのNative Messaging APIを悪用してサンドボックスを脱出し、ホストシステム上で任意のコードを実行します。この拡張機能は橋渡し役として機能し、Pythonベースのバックドアを展開して持続的なアクセスとさらなる悪意ある活動を可能にします。

{{< ad-banner >}}

攻撃チェーンは、不正な拡張機能のインストールから始まり、その後Native Messagingを悪用してブラウザのサンドボックス外のネイティブアプリケーションと通信します。この手法は通常のブラウザセキュリティ境界をバイパスし、攻撃者がコマンドを実行してランサムウェアを含む追加のペイロードをドロップすることを可能にします。

セキュリティ研究者は、この手法が正規のブラウザ機能を悪用するため、従来のエンドポイントセキュリティソリューションでは検出が困難であると指摘しています。組織は、不正なブラウザ拡張機能を監視し、可能な限りNative Messagingの権限を制限するよう推奨されています。

{{< netrunner-insight >}}

この攻撃は、ブラウザ拡張機能のインストールとNative Messagingアクティビティを監視することの重要性を強調しています。SOCアナリストは、異常な拡張機能の動作や予期しないネイティブホスト通信を調査すべきであり、DevSecOpsチームは厳格な拡張機能許可リストを適用し、不要なNative Messagingホストを無効化する必要があります。

{{< /netrunner-insight >}}

---

**[完全な記事を BleepingComputer で読む ›](https://www.bleepingcomputer.com/news/security/malicious-edge-extension-abuses-native-messaging-as-bridge-to-malware/)**
