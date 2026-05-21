---
title: "不完全なパッチ適用によりSonicWall VPNのMFAがバイパスされる"
date: "2026-05-21T10:35:14Z"
original_date: "2026-05-20T21:19:17"
lang: "ja"
translationKey: "sonicwall-vpn-mfa-bypassed-due-to-incomplete-patching"
author: "NewsBot (Validated by Federico Sella)"
description: "脅威アクターが未パッチのSonicWall Gen6 SSL-VPNアプライアンスに対してVPN認証情報をブルートフォースし、MFAをバイパスしてランサムウェアツールを展開している。"
original_url: "https://www.bleepingcomputer.com/news/security/hackers-bypass-sonicwall-vpn-mfa-due-to-incomplete-patching/"
source: "BleepingComputer"
severity: "High"
target: "SonicWall Gen6 SSL-VPNアプライアンス"
cve: null
cvss: null
kev: null
tags: ["news", "cybersecurity"]
news-categories: ["cybersecurity"]
layout: "news"
draft: false
---

脅威アクターが未パッチのSonicWall Gen6 SSL-VPNアプライアンスに対してVPN認証情報をブルートフォースし、MFAをバイパスしてランサムウェアツールを展開している。

{{< cyber-report severity="High" source="BleepingComputer" target="SonicWall Gen6 SSL-VPNアプライアンス" >}}

脅威アクターがSonicWall Gen6 SSL-VPNアプライアンスに対してVPN認証情報のブルートフォースと多要素認証（MFA）のバイパスを試みていることが確認された。この攻撃は不完全なパッチ適用を悪用し、攻撃者がランサムウェア作戦で一般的に使用されるツールを展開することを可能にしている。

{{< ad-banner >}}

この脆弱性により、攻撃者はVPN認証情報を侵害した後、内部ネットワークへの不正アクセスを獲得できる。侵入後、横方向に移動してランサムウェアペイロードを展開することが可能となり、これらのアプライアンスをリモートアクセスに依存する組織にとって重大なリスクとなる。

SonicWallはこの問題に対処するパッチをリリースしているが、これらの更新が不完全に適用されたままではシステムが露出した状態となる。組織は推奨されるすべてのパッチが完全にインストールされていることを確認し、不正なVPNアクセスの兆候を監視するよう求められている。

{{< netrunner-insight >}}

このインシデントは、徹底したパッチ管理の重要性を浮き彫りにしている。SOCアナリストは、すべてのSonicWall Gen6アプライアンスに最新のファームウェアが適用されていることを優先的に確認し、VPNログで異常な認証パターンを監視すべきである。DevSecOpsチームは、追加のMFAレイヤーとネットワークセグメンテーションを実装して、このようなバイパスを軽減することを検討すべきである。

{{< /netrunner-insight >}}

---

**[完全な記事を BleepingComputer で読む ›](https://www.bleepingcomputer.com/news/security/hackers-bypass-sonicwall-vpn-mfa-due-to-incomplete-patching/)**
