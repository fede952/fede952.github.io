---
title: "BdThemesのサプライチェーン攻撃により不正なWordPress管理者が作成される"
date: "2026-08-11T08:10:19Z"
original_date: "2026-08-11T05:48:44"
lang: "ja"
translationKey: "bdthemes-supply-chain-attack-creates-rogue-wordpress-admins"
slug: "bdthemes-supply-chain-attack-creates-rogue-wordpress-admins"
author: "NewsBot (Validated by Federico Sella)"
description: "サプライチェーン侵害がBdThemesのWordPressプラグインを襲う。ソースコードは一切変更されていないが、悪意のあるJSONによって不正な管理者アカウントが作成される。"
original_url: "https://thehackernews.com/2026/08/bdthemes-supply-chain-attack-poisons.html"
source: "The Hacker News"
severity: "High"
target: "BdThemesプラグインを使用するWordPressサイト"
cve: null
cvss: null
kev: null
tags: ["news", "cybersecurity"]
news-categories: ["cybersecurity"]
layout: "news"
draft: false
---

サプライチェーン侵害がBdThemesのWordPressプラグインを襲う。ソースコードは一切変更されていないが、悪意のあるJSONによって不正な管理者アカウントが作成される。

{{< cyber-report severity="High" source="The Hacker News" target="BdThemesプラグインを使用するWordPressサイト" >}}

サイバーセキュリティ研究者らは、WordPressプラグインベンダーであるBdThemesを標的としたサプライチェーン攻撃を公表した。この侵害により、WordPressプラグインチームはプラグインのダウンロードを一時的に無効化した。特筆すべきは、この攻撃が典型的なサプライチェーンインシデントとは異なり、公式のWordPress.orgリポジトリ内のソースコードファイルは一切変更されていないことだ。

{{< ad-banner >}}

その代わりに、この攻撃は悪意のあるJSONペイロードを利用して不正なWordPress管理者アカウントを作成する。この手法により、攻撃者はコアプラグインファイルを変更することなく影響を受けるサイトへの不正アクセスを獲得でき、標準的な整合性チェックによる検出がより困難になる。

Wordfenceの研究者Paolo Tresso氏は、この攻撃の異常な性質を強調し、ソースコードの変更がないことは、コードの整合性だけでなく包括的なサプライチェーン監視の必要性を浮き彫りにしていると述べた。

{{< netrunner-insight >}}

この攻撃は、コードの変更だけでなく、JSONなどの設定ファイルやデータファイルも監視することの重要性を強調している。SOCアナリストにとって、プラグインの更新は高リスクイベントとして扱い、ソースコードだけでなくすべてのファイルの整合性を検証すべきである。DevSecOpsは、予期しない管理者アカウントの作成をランタイムで監視し、コード以外の資産もカバーするファイル整合性監視を実装すべきである。

{{< /netrunner-insight >}}

---

**[完全な記事を The Hacker News で読む ›](https://thehackernews.com/2026/08/bdthemes-supply-chain-attack-poisons.html)**
