---
title: "Mandiant、Cisco SD-WANのゼロデイ脆弱性によるルートアクセス攻撃を公開"
date: "2026-06-25T10:15:15Z"
original_date: "2026-06-24T21:29:10"
lang: "ja"
translationKey: "mandiant-exposes-cisco-sd-wan-zero-day-root-access-attacks"
author: "NewsBot (Validated by Federico Sella)"
description: "新たな詳細により、攻撃者がCVE-2026-20245をゼロデイ攻撃で悪用し、Cisco Catalyst SD-WANデバイスに不正なルートアカウントを作成した方法が明らかになりました。"
original_url: "https://www.bleepingcomputer.com/news/security/mandiant-reveals-how-cisco-sd-wan-zero-day-attacks-gained-root-access/"
source: "BleepingComputer"
severity: "High"
target: "Cisco Catalyst SD-WANデバイス"
cve: "CVE-2026-20245"
cvss: null
kev: null
tags: ["news", "cybersecurity"]
news-categories: ["cybersecurity"]
layout: "news"
draft: false
---

新たな詳細により、攻撃者がCVE-2026-20245をゼロデイ攻撃で悪用し、Cisco Catalyst SD-WANデバイスに不正なルートアカウントを作成した方法が明らかになりました。

{{< cyber-report severity="High" source="BleepingComputer" target="Cisco Catalyst SD-WANデバイス" cve="CVE-2026-20245" >}}

Mandiantは、脅威アクターがCisco Catalyst SD-WANソフトウェアのゼロデイ脆弱性（CVE-2026-20245として追跡）を悪用し、標的のデバイスでルートアクセスを取得した方法に関する新たな技術的詳細を公開しました。この攻撃では不正なルートアカウントが作成され、持続的な不正アクセスが可能になりました。

{{< ad-banner >}}

この脆弱性は、Ciscoが最近のセキュリティアドバイザリでパッチを提供したもので、限定的かつ標的型の攻撃に使用されました。Mandiantの分析により、特定の攻撃チェーンが明らかになり、セキュリティアップデートを迅速に適用することの重要性が強調されています。

Cisco SD-WANソリューションを利用する組織は、不正なアカウントや異常なルートレベルの活動など、侵害の兆候がないかシステムを監査するよう推奨されます。このインシデントは、堅牢なパッチ管理とネットワークインフラの監視の重要性を浮き彫りにしています。

{{< netrunner-insight >}}

SOCアナリストは、Cisco SD-WANアプライアンスでの不正なアカウント作成や特権昇格イベントの監視を優先してください。DevSecOpsチームは、Ciscoのセキュリティパッチを迅速に展開し、SD-WAN管理インターフェースをセグメント化して攻撃対象領域を減らすことを検討すべきです。

{{< /netrunner-insight >}}

---

**[完全な記事を BleepingComputer で読む ›](https://www.bleepingcomputer.com/news/security/mandiant-reveals-how-cisco-sd-wan-zero-day-attacks-gained-root-access/)**
