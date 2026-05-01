---
title: "CISA、ABB PCM600のパストラバーサル脆弱性がRCEにつながると警告"
date: "2026-05-01T08:59:15Z"
original_date: "2026-04-30T12:00:00"
lang: "ja"
translationKey: "cisa-warns-of-abb-pcm600-path-traversal-flaw-leading-to-rce"
author: "NewsBot (Validated by Federico Sella)"
description: "ABB PCM600 バージョン1.5～2.13に、任意のコード実行を許す可能性のあるパストラバーサル脆弱性（CVE-2018-1002208）が存在します。バージョン2.14に更新してください。"
original_url: "https://www.cisa.gov/news-events/ics-advisories/icsa-26-120-02"
source: "CISA"
severity: "Medium"
target: "ABB PCM600"
cve: "CVE-2018-1002208"
cvss: null
kev: null
tags: ["news", "cybersecurity"]
news-categories: ["cybersecurity"]
layout: "news"
draft: false
---

ABB PCM600 バージョン1.5～2.13に、任意のコード実行を許す可能性のあるパストラバーサル脆弱性（CVE-2018-1002208）が存在します。バージョン2.14に更新してください。

{{< cyber-report severity="Medium" source="CISA" target="ABB PCM600" cve="CVE-2018-1002208" >}}

CISAは、保護制御IEDマネージャーであるABB PCM600の脆弱性に関する勧告（ICSA-26-120-02）を発表しました。CVE-2018-1002208として識別されるこの脆弱性は、SharpZip.dllライブラリに存在し、制限されたディレクトリへのパス名の制限が不適切であること（パストラバーサル）に関係します。悪用に成功すると、攻撃者は特別に細工したメッセージをシステムノードに送信し、任意のコード実行を引き起こす可能性があります。

{{< ad-banner >}}

影響を受ける製品バージョンは、PCM600 1.5から2.13までです。ABBはこの問題を修正するためにバージョン2.14をリリースしました。ただし、RE_630保護リレーはPCM600 2.14と互換性がないため、RE_630を使用している以前のバージョンのユーザーは、ABBの一般的なセキュリティ推奨事項に概説されているように、システムレベルの防御に依存する必要があります。

この勧告は、本製品が重要製造業セクター全体で世界中に展開されていることを強調しています。勧告ではCVSSスコアは提供されていませんが、コード実行の可能性があるため、可能な限り迅速なパッチ適用が求められます。組織はPCM600 2.14への更新を優先し、すぐに更新できないシステムについてはネットワークセグメンテーションとアクセス制御を実装する必要があります。

{{< netrunner-insight >}}

ABB PCM600のこのパストラバーサル脆弱性は、SharpZip.dllのようなレガシーな依存関係がリスクをもたらす可能性があることを思い出させます。SOCアナリストは、PCM600ノードへの異常なネットワークトラフィック、特に悪用の試みを示す可能性のある細工されたメッセージを監視してください。DevSecOpsエンジニアは、PCM600の全インスタンスをインベントリし、バージョン2.14へのアップグレードを計画するとともに、RE_630リレーとの互換性が補完的コントロールによって対処されていることを確認する必要があります。

{{< /netrunner-insight >}}

---

**[完全な記事を CISA で読む ›](https://www.cisa.gov/news-events/ics-advisories/icsa-26-120-02)**
