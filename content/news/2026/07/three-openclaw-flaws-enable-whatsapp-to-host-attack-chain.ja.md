---
title: "3つのOpenClaw脆弱性によりWhatsAppからホストへの攻撃チェーンが可能に"
date: "2026-07-11T08:46:01Z"
original_date: "2026-07-10T14:19:50"
lang: "ja"
translationKey: "three-openclaw-flaws-enable-whatsapp-to-host-attack-chain"
slug: "three-openclaw-flaws-enable-whatsapp-to-host-attack-chain"
author: "NewsBot (Validated by Federico Sella)"
description: "研究者が、ホスト上で認証情報の窃取、特権昇格、コード実行を可能にする可能性のある3つの高深刻度のOpenClaw脆弱性を詳細に報告"
original_url: "https://thehackernews.com/2026/07/researcher-details-whatsapp-to-host.html"
source: "The Hacker News"
severity: "High"
target: "OpenClaw AIアシスタント"
cve: null
cvss: 8.8
kev: null
tags: ["news", "cybersecurity"]
news-categories: ["cybersecurity"]
layout: "news"
draft: false
---

研究者が、ホスト上で認証情報の窃取、特権昇格、コード実行を可能にする可能性のある3つの高深刻度のOpenClaw脆弱性を詳細に報告

{{< cyber-report severity="High" source="The Hacker News" target="OpenClaw AIアシスタント" cvss="8.8" >}}

現在は修正済みの、OpenClawパーソナルAIアシスタントにおける3つのセキュリティ脆弱性の詳細が明らかになった。これらが悪用されると、ホスト上で認証情報の窃取、特権昇格、任意のコード実行が可能になる可能性がある。これらの脆弱性は、WhatsAppメッセージから始まる攻撃チェーンを概説した研究者によって公開された。

{{< ad-banner >}}

脆弱性の1つはGHSA-hjr6-g723-hmfmとして追跡され、CVSSスコア8.8で高深刻度と評価されている。他の2つの脆弱性の正確な性質は完全には明らかにされていないが、これらは総合的に、OpenClawをWhatsAppなどのメッセージングプラットフォームと統合しているユーザーに重大なリスクをもたらす。

攻撃チェーンは、AIアシスタントがメッセージを処理する機能を悪用し、攻撃者が特権を昇格させ、ホストシステム上で任意のコードを実行する可能性がある。ユーザーはこれらのリスクを軽減するために、最新のパッチを適用することが推奨される。

{{< netrunner-insight >}}

この攻撃チェーンは、AIアシスタントとメッセージングプラットフォームの統合に伴うリスクを浮き彫りにしている。SOCアナリストは、AIアシスタントコンポーネントから発生する異常なプロセス実行を監視すべきであり、DevSecOpsチームは、そのような統合がサンドボックス化され、迅速にパッチ適用されることを確実にする必要がある。

{{< /netrunner-insight >}}

---

**[完全な記事を The Hacker News で読む ›](https://thehackernews.com/2026/07/researcher-details-whatsapp-to-host.html)**
