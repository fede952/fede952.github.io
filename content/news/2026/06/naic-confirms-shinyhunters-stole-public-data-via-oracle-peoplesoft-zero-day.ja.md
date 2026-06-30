---
title: "NAIC、ShinyHuntersがOracle PeopleSoftのゼロデイを悪用して公開データを窃取したことを確認"
date: "2026-06-30T10:30:36Z"
original_date: "2026-06-29T20:30:28"
lang: "ja"
translationKey: "naic-confirms-shinyhunters-stole-public-data-via-oracle-peoplesoft-zero-day"
author: "NewsBot (Validated by Federico Sella)"
description: "全米保険監督官協会（NAIC）は、ShinyHuntersがOracle PeopleSoftのゼロデイ脆弱性を悪用し、公開データ、ログ、設定ファイルを窃取したと発表した。"
original_url: "https://www.bleepingcomputer.com/news/security/naic-says-public-data-stolen-in-shinyhunters-peoplesoft-breach/"
source: "BleepingComputer"
severity: "Medium"
target: "Oracle PeopleSoftサーバ"
cve: null
cvss: null
kev: null
tags: ["news", "cybersecurity"]
news-categories: ["cybersecurity"]
layout: "news"
draft: false
---

全米保険監督官協会（NAIC）は、ShinyHuntersがOracle PeopleSoftのゼロデイ脆弱性を悪用し、公開データ、ログ、設定ファイルを窃取したと発表した。

{{< cyber-report severity="Medium" source="BleepingComputer" target="Oracle PeopleSoftサーバ" >}}

全米保険監督官協会（NAIC）は、ShinyHunters恐喝グループがOracle PeopleSoftサーバのゼロデイ脆弱性を悪用してシステムに侵入したことを確認した。NAICの声明によると、攻撃者は公開データ、古いログ、設定ファイルのみを窃取した。

{{< ad-banner >}}

この侵害は、企業データベースを標的とし、被害者を恐喝することで知られるShinyHuntersグループによるものとされた。NAICは、窃取された情報はすでに公開されているか重要ではないものであり、機密性の高い消費者や保険会社のデータは侵害されていないと強調した。

このインシデントは、Oracle PeopleSoftのようなレガシーエンタープライズソフトウェアにおける未パッチの脆弱性がもたらすリスクを浮き彫りにしている。同様のシステムを使用する組織は、パッチ適用を優先し、ShinyHuntersの戦術に関連する侵害指標を監視するよう推奨される。

{{< netrunner-insight >}}

SOCチームは、ShinyHuntersがこれらのシステムを積極的に標的としているため、Oracle PeopleSoftのゼロデイ悪用を監視すべきである。PeopleSoftサーバを隔離し、ログを異常なアクセスパターンについて確認すること。たとえ「公開データ」の侵害であっても、風評被害や二次攻撃につながる可能性がある。

{{< /netrunner-insight >}}

---

**[完全な記事を BleepingComputer で読む ›](https://www.bleepingcomputer.com/news/security/naic-says-public-data-stolen-in-shinyhunters-peoplesoft-breach/)**
