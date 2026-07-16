---
title: "ロシアの脅威アクターがGoogle Gemini CLIを悪用し、ボットネット運用に利用"
date: "2026-07-16T09:08:49Z"
original_date: "2026-07-15T18:33:48"
lang: "ja"
translationKey: "google-gemini-cli-weaponized-by-russian-threat-actor-for-botnet-ops"
slug: "google-gemini-cli-weaponized-by-russian-threat-actor-for-botnet-ops"
author: "NewsBot (Validated by Federico Sella)"
description: "「bandcampro」として知られるロシア語圏の脅威アクターが、GoogleのオープンソースAIツール「Gemini CLI」を悪用し、ボットネットの運用やハッキングエージェントとして使用していたことが明らかになった。"
original_url: "https://www.bleepingcomputer.com/news/security/google-gemini-cli-abused-as-a-hacking-agent-malware-botnet-operator/"
source: "BleepingComputer"
severity: "Medium"
target: "Gemini CLIユーザー"
cve: null
cvss: null
kev: null
tags: ["news", "cybersecurity"]
news-categories: ["cybersecurity"]
layout: "news"
draft: false
---

「bandcampro」として知られるロシア語圏の脅威アクターが、GoogleのオープンソースAIツール「Gemini CLI」を悪用し、ボットネットの運用やハッキングエージェントとして使用していたことが明らかになった。

{{< cyber-report severity="Medium" source="BleepingComputer" target="Gemini CLIユーザー" >}}

「bandcampro」として追跡されるロシア語圏の脅威アクターが、GoogleのオープンソースAIツール「Gemini CLI」を悪用し、小規模なボットネットの運用やハッキングエージェントとして使用していることが確認された。このアクターは、同ツールの機能を活用してコマンド実行やデータ流出などの悪意ある活動を自動化し、正規のAIアシスタントをサイバー兵器に変えていた。

{{< ad-banner >}}

Gemini CLIの悪用は、脅威アクターが正規のAIツールを悪意ある目的に転用するという増加傾向を示している。CLIをボットネットのインフラに統合することで、アクターは検知を回避しながら運用を拡大できた。これは、ツールのトラフィックが通常のAI API使用と区別がつきにくいためである。

このインシデントは、組織が環境内でのAIツールの使用を監視し、厳格なアクセス制御を実施する必要性を強調している。セキュリティチームは、AI CLIツールを他のリモートアクセスユーティリティと同様に精査すべきであり、その自動化機能が攻撃の加速に悪用される可能性がある。

{{< netrunner-insight >}}

SOCアナリストにとって、この事例はネットワークアクセスを持つAI CLIツールの異常な使用を監視する必要性を思い出させる。DevSecOpsエンジニアは、自動化攻撃での悪用を防ぐために、そのようなツールをサンドボックス化または制限することを検討すべきだ。有用な自動化と悪意ある自動化の境界は薄い——AI CLIを潜在的な攻撃ベクトルとして扱うこと。

{{< /netrunner-insight >}}

---

**[完全な記事を BleepingComputer で読む ›](https://www.bleepingcomputer.com/news/security/google-gemini-cli-abused-as-a-hacking-agent-malware-botnet-operator/)**
