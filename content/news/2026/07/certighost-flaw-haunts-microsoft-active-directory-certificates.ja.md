---
title: "「Certighost」脆弱性がMicrosoft Active Directory証明書を悩ませる"
date: "2026-07-29T09:36:19Z"
original_date: "2026-07-28T16:38:48"
lang: "ja"
translationKey: "certighost-flaw-haunts-microsoft-active-directory-certificates"
slug: "certighost-flaw-haunts-microsoft-active-directory-certificates"
author: "NewsBot (Validated by Federico Sella)"
description: "Microsoftは、Active Directory環境で権限昇格を可能にする高深刻度の脆弱性にパッチを適用しました。SOCアナリストはパッチ適用を優先すべきです。"
original_url: "https://www.darkreading.com/vulnerabilities-threats/certighost-flaw-microsoft-active-directory-certificates"
source: "Dark Reading"
severity: "High"
target: "Microsoft Active Directory Certificate Services"
cve: null
cvss: null
kev: null
tags: ["news", "cybersecurity"]
news-categories: ["cybersecurity"]
layout: "news"
draft: false
---

Microsoftは、Active Directory環境で権限昇格を可能にする高深刻度の脆弱性にパッチを適用しました。SOCアナリストはパッチ適用を優先すべきです。

{{< cyber-report severity="High" source="Dark Reading" target="Microsoft Active Directory Certificate Services" >}}

Microsoftは、Active Directory Certificate Servicesにおける高深刻度の脆弱性「Certighost」にパッチを適用しました。この脆弱性により、攻撃者は権限を昇格させ、Active Directory環境を侵害する可能性があります。この欠陥は、2026年7月28日にDark Readingによって公開されました。

{{< ad-banner >}}

この脆弱性は証明書登録プロセスに影響し、低レベルのアクセス権を持つ脅威アクターが権限をドメイン管理者に昇格させることを可能にします。これにより、ADインフラストラクチャ全体が侵害され、証明書を偽造して任意のユーザーやデバイスになりすますことが可能になる可能性があります。

Microsoft Active Directory Certificate Servicesを使用している組織は、直ちに最新のセキュリティ更新プログラムを適用することを推奨します。この脆弱性は、AD環境内で信頼を維持する上での証明書サービスの重要性を浮き彫りにしています。

{{< netrunner-insight >}}

これは典型的なAD証明書サービスの攻撃ベクトルです。証明書テンプレートを強化し、登録権限を厳密に制御してください。直ちにパッチを適用し、異常な証明書要求や権限昇格を監視してください。

{{< /netrunner-insight >}}

---

**[完全な記事を Dark Reading で読む ›](https://www.darkreading.com/vulnerabilities-threats/certighost-flaw-microsoft-active-directory-certificates)**
