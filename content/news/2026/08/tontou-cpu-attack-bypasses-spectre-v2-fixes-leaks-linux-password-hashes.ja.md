---
title: "TONTOU CPU攻撃がSpectre v2の修正を回避し、Linuxのパスワードハッシュを漏洩"
date: "2026-08-10T08:26:15Z"
original_date: "2026-08-06T18:03:45"
lang: "ja"
translationKey: "tontou-cpu-attack-bypasses-spectre-v2-fixes-leaks-linux-password-hashes"
slug: "tontou-cpu-attack-bypasses-spectre-v2-fixes-leaks-linux-password-hashes"
author: "NewsBot (Validated by Federico Sella)"
description: "研究者らは、最近のSpectre v2緩和策を回避するTONTOU攻撃を開発し、Linuxシステムからパスワードハッシュを含む秘密情報の漏洩に成功した。"
original_url: "https://www.bleepingcomputer.com/news/security/new-tontou-cpu-attack-bypasses-spectre-v2-fixes-leaks-linux-password-hashes/"
source: "BleepingComputer"
severity: "High"
target: "Linuxシステム"
cve: null
cvss: null
kev: null
tags: ["news", "cybersecurity"]
news-categories: ["cybersecurity"]
layout: "news"
draft: false
---

研究者らは、最近のSpectre v2緩和策を回避するTONTOU攻撃を開発し、Linuxシステムからパスワードハッシュを含む秘密情報の漏洩に成功した。

{{< cyber-report severity="High" source="BleepingComputer" target="Linuxシステム" >}}

セキュリティ研究者らは、Spectre v2の脆弱性に対する最近の緩和策を回避する「TONTOU」と名付けられた新しい投機的実行攻撃を発表した。この攻撃は、以前サイドチャネル漏洩を防ぐためにパッチが適用されたCPUの分岐予測メカニズムを標的とする。これらの防御のギャップを悪用することで、研究者らはLinuxマシンのカーネルメモリから機密データを抽出することに成功した。

{{< ad-banner >}}

概念実証エクスプロイトは、標的システムからパスワードハッシュを漏洩させることで、この問題の深刻さを示している。これは、この攻撃がユーザーの認証情報を侵害し、特権を昇格させる可能性があることを示唆している。この発見は、投機的実行サイドチャネル攻撃を完全に緩和することの継続的な課題を浮き彫りにしており、以前の修正にもかかわらず新たな亜種が出現し続けている。

研究者らはまだ完全な技術的詳細を公開していないが、この研究はCPUセキュリティにおける継続的な警戒の必要性を強調している。システム管理者は、CPUベンダーやLinuxディストリビューションからの更新を監視し、カーネルアドレス空間レイアウトのランダム化（KASLR）やマイクロコード更新などの追加の強化策を検討することを推奨する。

{{< netrunner-insight >}}

この攻撃は、投機的実行の脆弱性が完全には解決されていないことを痛感させるものである。SOCアナリストはパッチ適用を優先し、悪用の兆候を監視すべきであり、DevSecOpsエンジニアはサイドチャネルリスクについて脅威モデルを見直すべきである。パスワードハッシュの漏洩の可能性を考慮すると、Linuxカーネルの更新とCPUマイクロコードへの即時の対応が求められる。

{{< /netrunner-insight >}}

---

**[完全な記事を BleepingComputer で読む ›](https://www.bleepingcomputer.com/news/security/new-tontou-cpu-attack-bypasses-spectre-v2-fixes-leaks-linux-password-hashes/)**
