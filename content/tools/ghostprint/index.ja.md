---
title: "GhostPrint：ブラウザフィンガープリント診断 — あなたはどれだけ追跡されやすい？"
description: "ブラウザがすべてのサイトに渡している見えない指紋——GPU、canvas、フォント、音声など——を可視化し、ユニークさをスコア化。100%ブラウザ内で動作し、何もアップロードしません。"
date: 2026-07-06
tags: ["privacy", "security", "developer-tools", "fingerprinting"]
keywords: ["ブラウザフィンガープリント診断", "私はユニークか", "デバイスフィンガープリント", "canvas フィンガープリント", "どれだけ追跡されるか", "ブラウザフィンガープリンティング", "webgl 指紋", "オーディオ指紋", "オンラインプライバシー診断", "トラッキング対策診断"]
layout: "tool"
draft: false
tool_file: "/tools/ghostprint/"
tool_height: "2200"
schema_json: >
  {"@context": "https://schema.org", "@type": "SoftwareApplication", "name": "GhostPrint — ブラウザフィンガープリント診断", "description": "GPU、canvas、音声、フォントなどからブラウザのユニークさと追跡されやすさをスコア化する、無料のクライアントサイド・フィンガープリント診断。", "applicationCategory": "SecurityApplication", "operatingSystem": "Web", "browserRequirements": "Requires JavaScript", "isAccessibleForFree": true, "offers": {"@type": "Offer", "price": "0", "priceCurrency": "USD"}}
---

## なぜ指紋は Cookie より厄介なのか

Cookie は簡単にブロックできます。しかし**ブラウザフィンガープリント**はそうはいきません。デバイス、GPU、フォント、画面、設定の組み合わせ方そのものが識別子となり、サイトをまたいであなたを追跡します——しかも**シークレットモード、Cookie削除、ほとんどの「プライベート」閲覧をすり抜けます。** GhostPrint は数秒であなたの指紋を表示し、ユニークさのスコアと、漏れているすべてのシグナルの内訳を示します。

核心はここです。以下のシグナルはすべて**あなたのブラウザ内**で読み取られ、**どこにも**送信されません——アップロードもログもサーバーもなし。しかし、あなたが訪れるどんなサイトも、許可を求めることなく静かにこれらの値を読み取れます。広告や不正検知のネットワークはまさにそれを行っています。ページを再読み込みすればデータは消えますが、トラッカーはそのボタンを用意してくれません。

## GhostPrint が読み取るもの

- **ハードウェアと GPU** — グラフィックチップ（WebGL経由）、CPUコア数、メモリ、画面情報
- **レンダリング指紋** — canvas と音声のハッシュ：あなたの環境に固有のピクセル/サンプル単位の癖
- **環境** — インストール済みフォント、タイムゾーン、言語、プラットフォーム、表示設定
- **プライバシーシグナル** — Cookie、Do-Not-Track、Global Privacy Control の状態

## ゴーストを薄める方法

- **Tor Browser** は最高水準——すべてのユーザーが意図的に同一に見えるよう作られています。
- **Firefox** には `privacy.resistFingerprinting` があり、**Brave** は既定で canvas と音声をランダム化します。
- 対策拡張機能や WebGL の無効化は有効です——そして逆説的に、珍しいハードウェアや稀なフォントはあなたを*より*識別しやすくします。

上のスキャンを実行してユニークさのスコアを確認し、共有用カードをダウンロードして他のブラウザと比べてみてください。
