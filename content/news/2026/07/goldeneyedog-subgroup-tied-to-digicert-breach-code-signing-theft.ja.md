---
title: "GoldenEyeDogのサブグループ、DigiCert侵害とコード署名窃取に関連"
date: "2026-07-18T08:46:42Z"
original_date: "2026-07-17T16:39:16"
lang: "ja"
translationKey: "goldeneyedog-subgroup-tied-to-digicert-breach-code-signing-theft"
slug: "goldeneyedog-subgroup-tied-to-digicert-breach-code-signing-theft"
author: "NewsBot (Validated by Federico Sella)"
description: "研究者らは、2026年4月のDigiCertインシデントを、中国のサイバー犯罪グループGoldenEyeDogのサブグループであるCylindricalCanineによるものと特定した。このグループはギャンブルやゲーム業界を標的とすることで知られている。"
original_url: "https://thehackernews.com/2026/07/goldeneyedog-subgroup-linked-to.html"
source: "The Hacker News"
severity: "High"
target: "DigiCertのコード署名インフラ"
cve: null
cvss: null
kev: null
tags: ["news", "cybersecurity"]
news-categories: ["cybersecurity"]
layout: "news"
draft: false
---

研究者らは、2026年4月のDigiCertインシデントを、中国のサイバー犯罪グループGoldenEyeDogのサブグループであるCylindricalCanineによるものと特定した。このグループはギャンブルやゲーム業界を標的とすることで知られている。

{{< cyber-report severity="High" source="The Hacker News" target="DigiCertのコード署名インフラ" >}}

サイバーセキュリティ研究者らは、2026年4月のDigiCertにおけるセキュリティインシデントを、CylindricalCanineと名付けられた脅威活動クラスタによるものと特定した。このグループは、GoldenEyeDog（APT-Q-27、Dragon Breath、Miuuti Groupとしても知られる）のサブグループであり、歴史的にギャンブルやゲーム業界を標的とする中国のサイバー犯罪グループである。

{{< ad-banner >}}

この侵害にはコード署名証明書の窃取が含まれており、脅威アクターが正当な資格情報で悪意のあるソフトウェアに署名し、セキュリティ制御を回避する可能性がある。Expelはこの事件の技術的詳細を公開し、その高度な性質を強調した。

DigiCert発行の証明書に依存する組織は、証明書インベントリを確認し、不正使用がないか監視すべきである。このインシデントは、信頼された認証局を標的としたサプライチェーン攻撃のリスクを浮き彫りにしている。

{{< netrunner-insight >}}

SOCアナリスト向け：コード署名の異常や予期しない証明書の使用を優先的に監視すること。DevSecOpsチームは、厳格な証明書ライフサイクル管理を実施し、窃取による露出を制限するために短期証明書の使用を検討すべきである。

{{< /netrunner-insight >}}

---

**[完全な記事を The Hacker News で読む ›](https://thehackernews.com/2026/07/goldeneyedog-subgroup-linked-to.html)**
