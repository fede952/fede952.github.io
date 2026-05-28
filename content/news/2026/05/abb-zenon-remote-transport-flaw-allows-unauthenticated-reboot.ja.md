---
title: "ABB Zenon Remote Transportの欠陥により、認証なしで再起動が可能に"
date: "2026-05-28T10:50:49Z"
original_date: "2026-05-26T12:00:00"
lang: "ja"
translationKey: "abb-zenon-remote-transport-flaw-allows-unauthenticated-reboot"
author: "NewsBot (Validated by Federico Sella)"
description: "CISAは、ABB Ability ZenonのCVE-2025-8754について警告しています。この脆弱性により、Remote Transport Serviceを介した不正なシステム再起動が可能になります。現在のところ、活発な悪用は報告されていません。"
original_url: "https://www.cisa.gov/news-events/ics-advisories/icsa-26-146-03"
source: "CISA"
severity: "High"
target: "ABB Ability Zenonシステム"
cve: "CVE-2025-8754"
cvss: 7.5
kev: null
tags: ["news", "cybersecurity"]
news-categories: ["cybersecurity"]
layout: "news"
draft: false
---

CISAは、ABB Ability ZenonのCVE-2025-8754について警告しています。この脆弱性により、Remote Transport Serviceを介した不正なシステム再起動が可能になります。現在のところ、活発な悪用は報告されていません。

{{< cyber-report severity="High" source="CISA" target="ABB Ability Zenonシステム" cve="CVE-2025-8754" cvss="7.5" >}}

CISAは、ABB Ability ZenonのRemote Transport Serviceにおける認証欠落の脆弱性を詳細に説明した勧告（ICSA-26-146-03）を公開しました。CVE-2025-8754として追跡され、CVSSスコア7.5のこの欠陥により、攻撃者は適切な認証情報なしでシステムの再起動を引き起こすことができます。影響を受けるバージョンは7.50から14までです。

{{< ad-banner >}}

悪用には事前のネットワークアクセスが必要であり、攻撃者は標的のZenonシステムと同じネットワーク上にいる必要があります。ABBは、デフォルト設定ではzensyssrv.exeサービスが自動的に起動するが、Remote Transport Serviceを使用するにはユーザーがパスワードを設定する必要があると述べています。現時点では、実際の悪用の証拠はありません。

この勧告は、ABB Ability Zenonが化学、エネルギー、医療、上下水道システムなどの重要インフラセクターに広く展開されていることを強調しています。影響を受けるバージョンを使用している組織は、潜在的なサービス拒否攻撃を防ぐために、ABBが提供する緩和策やアップデートを直ちに適用する必要があります。

{{< netrunner-insight >}}

SOCアナリスト向け：ネットワークセグメンテーションを優先してZenonシステムへの露出を制限し、Remote Transport Serviceのパスワードが設定され、強力であることを確認してください。DevSecOpsチームは、zensyssrv.exeサービスが信頼されていないネットワークに公開されていないことを確認し、ベンダーのパッチが利用可能になり次第適用してください。CVSS 7.5と重要インフラへの影響を考慮し、活発な悪用がなくても、これを優先度の高い発見事項として扱ってください。

{{< /netrunner-insight >}}

---

**[完全な記事を CISA で読む ›](https://www.cisa.gov/news-events/ics-advisories/icsa-26-146-03)**
