---
title: "ソフトウェア開発におけるLLM：新たな脆弱性とOWASP脅威"
date: "2026-07-02T09:55:59Z"
original_date: "2026-07-01T14:47:31"
lang: "ja"
translationKey: "llms-in-software-development-new-vulnerabilities-and-owasp-threats"
author: "NewsBot (Validated by Federico Sella)"
description: "AIを活用したコーディングアシスタントは開発を加速させる一方、安全でないコード、幻覚ライブラリ、プロンプトインジェクション、データ漏洩などのリスクをもたらします。OWASP脅威と安全な導入戦略について学びましょう。"
original_url: "https://www.cybersecurity360.it/soluzioni-aziendali/intelligenza-artificiale-e-vulnerabilita-il-ruolo-dei-modelli-llm-nel-codice-applicativo/"
source: "Cybersecurity360"
severity: "Medium"
target: "LLMを使用するソフトウェア開発パイプライン"
cve: null
cvss: null
kev: null
tags: ["news", "cybersecurity"]
news-categories: ["cybersecurity"]
layout: "news"
draft: false
---

AIを活用したコーディングアシスタントは開発を加速させる一方、安全でないコード、幻覚ライブラリ、プロンプトインジェクション、データ漏洩などのリスクをもたらします。OWASP脅威と安全な導入戦略について学びましょう。

{{< cyber-report severity="Medium" source="Cybersecurity360" target="LLMを使用するソフトウェア開発パイプライン" >}}

大規模言語モデル（LLM）はアプリケーションコードの生成にますます利用され、開発者の生産性を向上させる一方で、新たなセキュリティリスクも導入しています。自動生成されたコードには、インジェクションの欠陥、安全でない暗号化手法、または専門的なレビューなしでは検出が難しい論理エラーなどの脆弱性が含まれる可能性があります。

{{< ad-banner >}}

主要な懸念事項は幻覚（ハルシネーション）であり、LLMが存在しないライブラリやAPIを提案することで、開発者が知らずに悪意のあるパッケージをインポートするとサプライチェーン攻撃につながる可能性があります。さらに、プロンプトインジェクション攻撃はLLMの動作を操作する可能性があり、データ漏洩はトレーニングデータやユーザーとのやり取りに埋め込まれた機密情報を露出させる可能性があります。

LLMアプリケーション向けのOWASP Top 10は、プロンプトインジェクション、安全でない出力処理、トレーニングデータのポイズニングなどの脅威を強調しています。リスクを軽減するために、組織は厳格なコードレビューを実施し、静的解析ツールを使用し、LLMの機密データへのアクセスを制限し、AI生成コードに合わせた安全なコーディングガイドラインを採用すべきです。

{{< netrunner-insight >}}

SOCアナリストとDevSecOpsエンジニア向け：LLMが生成したコードは信頼できない入力として扱ってください。CI/CDパイプラインに自動セキュリティスキャンを統合し、AIが提案する外部依存関係に対して厳格な検証を実施してください。プロンプトインジェクションやデータ漏洩による影響範囲を制限するために、LLMを最小権限で隔離された環境にデプロイすることを検討してください。

{{< /netrunner-insight >}}

---

**[完全な記事を Cybersecurity360 で読む ›](https://www.cybersecurity360.it/soluzioni-aziendali/intelligenza-artificiale-e-vulnerabilita-il-ruolo-dei-modelli-llm-nel-codice-applicativo/)**
