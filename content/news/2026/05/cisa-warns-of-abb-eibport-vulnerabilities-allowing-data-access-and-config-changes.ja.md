---
title: "CISA、ABB EIBPORTの脆弱性によりデータアクセスと設定変更の可能性を警告"
date: "2026-05-29T10:43:33Z"
original_date: "2026-05-28T12:00:00"
lang: "ja"
translationKey: "cisa-warns-of-abb-eibport-vulnerabilities-allowing-data-access-and-config-changes"
author: "NewsBot (Validated by Federico Sella)"
description: "ABB EIBPORTデバイスは、クロスサイトスクリプティングとセッションIDの盗難に対して脆弱です。ファームウェアバージョン3.9.2へのアップデートが利用可能です。"
original_url: "https://www.cisa.gov/news-events/ics-advisories/icsa-26-148-03"
source: "CISA"
severity: "High"
target: "ABB EIBPORTデバイス"
cve: "CVE-2021-22291"
cvss: null
kev: null
tags: ["news", "cybersecurity"]
news-categories: ["cybersecurity"]
layout: "news"
draft: false
---

ABB EIBPORTデバイスは、クロスサイトスクリプティングとセッションIDの盗難に対して脆弱です。ファームウェアバージョン3.9.2へのアップデートが利用可能です。

{{< cyber-report severity="High" source="CISA" target="ABB EIBPORTデバイス" cve="CVE-2021-22291" >}}

CISAは、ABB EIBPORTデバイス、特にEIBPORT V3 KNXおよびEIBPORT V3 KNX GSMモデルにおける複数の脆弱性を詳細に説明した勧告（ICSA-26-148-03）を発表しました。これらの脆弱性には、クロスサイトスクリプティング（XSS）の欠陥（CWE-79）とセッションIDの盗難の問題（CVE-2021-22291）が含まれており、攻撃者がデバイスに保存された機密情報にアクセスし、その設定を変更する可能性があります。

{{< ad-banner >}}

影響を受けるファームウェアバージョンは3.9.2より前のものです。ABBは、これらの非公開で報告された脆弱性を修正するためのファームウェアアップデートをリリースしました。これらの製品は、重要製造業や情報技術分野において世界中で展開されており、ベンダーはスイスに本社を置いています。

勧告ではCVSSスコアは提供されていませんが、デバイスの整合性と機密性への潜在的な影響を考慮すると、迅速なパッチ適用が求められます。影響を受けるABB EIBPORTデバイスを使用している組織は、悪用のリスクを軽減するために、できるだけ早くファームウェアアップデートを適用する必要があります。

{{< netrunner-insight >}}

SOCアナリストは、ファームウェアが3.9.2未満のABB EIBPORTデバイスのスキャンを優先し、異常な設定変更やセッションの異常を監視してください。DevSecOpsチームは、特にビルディングオートメーションや重要インフラにおけるデバイスの役割を考慮し、このファームウェアアップデートをパッチ管理パイプラインに統合する必要があります。

{{< /netrunner-insight >}}

---

**[完全な記事を CISA で読む ›](https://www.cisa.gov/news-events/ics-advisories/icsa-26-148-03)**
