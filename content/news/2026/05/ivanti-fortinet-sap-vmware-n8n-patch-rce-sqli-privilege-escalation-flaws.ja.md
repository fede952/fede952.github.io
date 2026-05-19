---
title: "Ivanti、Fortinet、SAP、VMware、n8nがRCE、SQLi、権限昇格の脆弱性を修正"
date: "2026-05-19T10:36:29Z"
original_date: "2026-05-18T10:54:05"
lang: "ja"
translationKey: "ivanti-fortinet-sap-vmware-n8n-patch-rce-sqli-privilege-escalation-flaws"
author: "NewsBot (Validated by Federico Sella)"
description: "複数のベンダーが、Ivanti XtractionのCVE-2026-8043（CVSS 9.6）を含む重大な脆弱性に対するセキュリティ修正をリリース。この脆弱性は情報漏洩やクライアントサイド攻撃につながる可能性がある。"
original_url: "https://thehackernews.com/2026/05/ivanti-fortinet-sap-vmware-n8n-patch.html"
source: "The Hacker News"
severity: "Critical"
target: "Ivanti Xtraction"
cve: "CVE-2026-8043"
cvss: 9.6
kev: null
tags: ["news", "cybersecurity"]
news-categories: ["cybersecurity"]
layout: "news"
draft: false
---

複数のベンダーが、Ivanti XtractionのCVE-2026-8043（CVSS 9.6）を含む重大な脆弱性に対するセキュリティ修正をリリース。この脆弱性は情報漏洩やクライアントサイド攻撃につながる可能性がある。

{{< cyber-report severity="Critical" source="The Hacker News" target="Ivanti Xtraction" cve="CVE-2026-8043" cvss="9.6" >}}

Ivanti、Fortinet、n8n、SAP、VMwareは、認証バイパスや任意のコード実行に悪用される可能性のある複数の脆弱性に対処するセキュリティパッチをリリースした。最も深刻な欠陥はIvanti XtractionのCVE-2026-8043で、CVSSスコアは9.6であり、ファイル名の外部制御を許し、情報漏洩やクライアントサイド攻撃につながる。

{{< ad-banner >}}

他のベンダーも、SQLインジェクションや権限昇格の脆弱性を含む高深刻度の問題に対処した。組織は、特にインターネットに公開されているシステムについて、これらの欠陥のパッチ適用を優先するよう求められている。これらは連鎖的に悪用され、システム全体の侵害につながる可能性がある。

まだ活発な悪用は報告されていないが、攻撃対象領域の広さと高いCVSSスコアを考慮すると、セキュリティチームによる即時の対応が必要である。定期的な脆弱性スキャンとパッチ管理はリスクを軽減するために重要である。

{{< netrunner-insight >}}

SOCアナリストは、Ivanti XtractionのCVE-2026-8043パッチを優先すべきである。これはCVSSスコアが重大であり、クライアントサイド攻撃の可能性があるためである。DevSecOpsチームは、影響を受けるすべてのシステムが更新されていることを確認し、悪用の兆候を監視する必要がある。ファイル名の外部制御は、データの流出や横方向の移動につながる可能性がある。

{{< /netrunner-insight >}}

---

**[完全な記事を The Hacker News で読む ›](https://thehackernews.com/2026/05/ivanti-fortinet-sap-vmware-n8n-patch.html)**
