---
title: "CISA、活発なWebシェル攻撃を受けPTC WindchillのRCE脆弱性をKEVに追加"
date: "2026-06-27T09:25:09Z"
original_date: "2026-06-26T12:31:56"
lang: "ja"
translationKey: "cisa-adds-ptc-windchill-rce-flaw-to-kev-amid-active-web-shell-attacks"
author: "NewsBot (Validated by Federico Sella)"
description: "CISAは、PTC Windchill PDMlinkおよびFlexPLMにおける重大なリモートコード実行の脆弱性を、活発な悪用が確認されたため既知の悪用脆弱性カタログに追加しました。"
original_url: "https://thehackernews.com/2026/06/cisa-adds-exploited-ptc-windchill-rce.html"
source: "The Hacker News"
severity: "Critical"
target: "PTC Windchill PDMlink and FlexPLM"
cve: null
cvss: null
kev: true
tags: ["news", "cybersecurity"]
news-categories: ["cybersecurity"]
layout: "news"
draft: false
---

CISAは、PTC Windchill PDMlinkおよびFlexPLMにおける重大なリモートコード実行の脆弱性を、活発な悪用が確認されたため既知の悪用脆弱性カタログに追加しました。

{{< cyber-report severity="Critical" source="The Hacker News" target="PTC Windchill PDMlink and FlexPLM" kev="true" >}}

米国サイバーセキュリティ・インフラストラクチャセキュリティ庁（CISA）は、PTC Windchill PDMlinkおよびPTC FlexPLMに影響する重大なリモートコード実行の脆弱性を、既知の悪用脆弱性（KEV）カタログに追加しました。この決定は、活発な悪用の証拠に基づいており、これらのエンタープライズ製品データ管理（PDM）および製品ライフサイクル管理（PLM）システムを標的とした進行中のWebシェル攻撃が報告されています。

{{< ad-banner >}}

発表では特定のCVE識別子は開示されていませんが、この脆弱性は、攻撃者が影響を受けるシステム上で任意のコードを実行できる可能性がある重大なRCE欠陥として説明されています。これらの製品を使用する組織は、パッチ適用を優先し、環境に侵害の兆候がないか確認するよう求められています。悪用されるとシステム全体が乗っ取られる可能性があります。

CISAのKEVカタログは、連邦機関に対する拘束力のある運用指令として機能し、指定された期間内に是正することを要求しています。民間組織はこれを高優先度の脅威として扱い、ネットワークのセグメンテーションや異常なWebシェルアクティビティの監視などの緩和策を実施することを強く推奨します。

{{< netrunner-insight >}}

SOCアナリストは、公開されたWindchillサーバー上のWebシェルの兆候を優先的に調査してください。アプリケーションから生成された異常な子プロセスや、未知のIPアドレスへの送信接続を探します。DevSecOpsチームは、利用可能なパッチを直ちに適用し、パッチ適用が遅れる場合は仮想パッチやWAFルールの導入を検討してください。PLMシステムはパッチ管理で見落とされがちであり、ランサムウェアグループにとって魅力的な標的であることを忘れてはなりません。

{{< /netrunner-insight >}}

---

**[完全な記事を The Hacker News で読む ›](https://thehackernews.com/2026/06/cisa-adds-exploited-ptc-windchill-rce.html)**
