---
title: "RustDuckボットネットがルーターやカメラを乗っ取りDDoS攻撃"
date: "2026-07-01T10:41:08Z"
original_date: "2026-06-30T17:45:25"
lang: "ja"
translationKey: "rustduck-botnet-hijacks-routers-cameras-for-ddos"
author: "NewsBot (Validated by Federico Sella)"
description: "RustDuckと呼ばれる新しい2段階マルウェアファミリーが、家庭用ルーター、IPカメラ、Androidボックス、セキュリティが不十分なサーバーを乗っ取り、DDoSネットワークを構築しています。2026年2月から追跡されています。"
original_url: "https://thehackernews.com/2026/06/rustduck-botnet-rebuilds-in-rust-to.html"
source: "The Hacker News"
severity: "High"
target: "ルーター、IPカメラ、Androidボックス、サーバー"
cve: null
cvss: null
kev: null
tags: ["news", "cybersecurity"]
news-categories: ["cybersecurity"]
layout: "news"
draft: false
---

RustDuckと呼ばれる新しい2段階マルウェアファミリーが、家庭用ルーター、IPカメラ、Androidボックス、セキュリティが不十分なサーバーを乗っ取り、DDoSネットワークを構築しています。2026年2月から追跡されています。

{{< cyber-report severity="High" source="The Hacker News" target="ルーター、IPカメラ、Androidボックス、サーバー" >}}

QiAnXinのXLabの研究者は、2026年2月からRustDuckと呼ばれる新しい2段階マルウェアファミリーを追跡しています。このボットネットは、家庭用ルーター、IPカメラ、Androidボックス、セキュリティが不十分なサーバーを乗っ取り、DDoS攻撃によってウェブサイトやオンラインサービスをオフラインにするネットワークに組み込んでいます。

{{< ad-banner >}}

このマルウェアは、メモリ安全な言語であるRustで再構築されている点で注目に値し、分析やリバースエンジニアリングを複雑にします。ボットネットの現在の規模は大きくありませんが、その急速な進化と適応性は、インターネットインフラに対する脅威を増大させています。

RustDuckは、Rustのパフォーマンスと安全性の機能を活用して、より回復力があり検出が困難なマルウェアを作成することで、ボットネット開発の転換を示しています。最終的な目標は、主要な標的をダウンさせることができる堅牢なDDoSネットワークを構築することです。

{{< netrunner-insight >}}

SOCアナリスト向け：IoTデバイスやルーターからの異常なアウトバウンドトラフィックを監視してください。RustDuckの2段階感染は従来のシグネチャを回避する可能性があります。DevSecOpsチームは、厳格なネットワークセグメンテーションを実施し、露出したデバイスで不要なサービスを無効にして攻撃対象領域を減らすべきです。

{{< /netrunner-insight >}}

---

**[完全な記事を The Hacker News で読む ›](https://thehackernews.com/2026/06/rustduck-botnet-rebuilds-in-rust-to.html)**
