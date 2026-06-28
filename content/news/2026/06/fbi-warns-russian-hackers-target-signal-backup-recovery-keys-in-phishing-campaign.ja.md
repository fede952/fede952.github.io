---
title: "FBI、ロシア人ハッカーがフィッシングキャンペーンでSignalのバックアップ復旧キーを標的に"
date: "2026-06-28T09:56:23Z"
original_date: "2026-06-26T22:06:17"
lang: "ja"
translationKey: "fbi-warns-russian-hackers-target-signal-backup-recovery-keys-in-phishing-campaign"
author: "NewsBot (Validated by Federico Sella)"
description: "FBIとCISAは、ロシアの情報機関に関連するフィッシング攻撃がSignalのバックアップ復旧キーを盗み、被害者の過去のメッセージにアクセス可能にしていると警告。"
original_url: "https://www.bleepingcomputer.com/news/security/fbi-russian-hackers-now-target-signal-backup-recovery-keys/"
source: "BleepingComputer"
severity: "High"
target: "Signalユーザー"
cve: null
cvss: null
kev: null
tags: ["news", "cybersecurity"]
news-categories: ["cybersecurity"]
layout: "news"
draft: false
---

FBIとCISAは、ロシアの情報機関に関連するフィッシング攻撃がSignalのバックアップ復旧キーを盗み、被害者の過去のメッセージにアクセス可能にしていると警告。

{{< cyber-report severity="High" source="BleepingComputer" target="Signalユーザー" >}}

FBIとCISAは、ロシアの情報機関に起因するフィッシングキャンペーンがSignalのバックアップ復旧キーを標的にするよう進化したとの共同警告を発表した。これらのキーは通常、新しい端末でメッセージ履歴を復元するために使用されるが、盗まれると攻撃者が被害者の過去の会話や連絡先にアクセスできるようになる。

{{< ad-banner >}}

このキャンペーンは当初Signalのログイン認証情報を盗むことに焦点を当てていたが、現在は復旧キーの流出に拡大している。攻撃者は偽のSignalグループ招待やセキュリティアラートなどのソーシャルエンジニアリング手法を用いて、ユーザーを騙して復旧キーを開示させる。

機密通信にSignalを使用する組織や個人は、登録ロックや画面ロックなどの追加セキュリティ対策を有効にし、復旧キーやログイン認証情報の要求の正当性を確認するよう求められている。

{{< netrunner-insight >}}

SOCアナリストは、Signalのグループ招待やセキュリティアラートを装ったフィッシングの誘引を監視すべきである。これらは現在、復旧キーを収集するために使用されている。DevSecOpsチームは多要素認証を強制し、正当なサービスが一方的なメッセージで復旧キーやパスワードを要求することは決してないとユーザーに教育すべきである。

{{< /netrunner-insight >}}

---

**[完全な記事を BleepingComputer で読む ›](https://www.bleepingcomputer.com/news/security/fbi-russian-hackers-now-target-signal-backup-recovery-keys/)**
