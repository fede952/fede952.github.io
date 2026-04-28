---
title: "AIにお金を払うのはもうやめよう：DeepSeek と Llama 3 を無料でローカル実行する方法"
date: 2025-02-02
description: "Ollama を使って DeepSeek や Llama 3 などの強力な AI モデルを自分の PC で無料で実行する方法を解説。完全なプライバシー、月額料金ゼロ、オフライン対応。"
tags: ["AI", "Ollama", "Privacy", "Tutorial", "LocalLLM"]
categories: ["Guides", "Artificial Intelligence"]
author: "Federico Sella"
draft: false
---

強力な AI アシスタントを使うために月額 20 ドルのサブスクリプションは必要ありません。**Ollama** という無料のオープンソースツールを使えば、**Meta の Llama 3** や **DeepSeek-R1** を含む最先端の大規模言語モデルを自分のコンピュータ上で直接実行できます。クラウドなし、アカウントなし、データがマシンから出ることは一切ありません。

このガイドでは、10 分以内にセットアップ全体を完了する方法を説明します。

## なぜ AI をローカルで実行するのか？

### 完全なプライバシー

クラウド AI サービスを使用すると、入力するすべてのプロンプトがリモートサーバーに送信されます。コードスニペット、ビジネスアイデア、個人的な質問——すべてです。**ローカル LLM** なら、会話はあなたのハードウェア上に留まります。それだけです。

### 月額料金ゼロ

ChatGPT Plus は月額 20 ドル。Claude Pro は月額 20 ドル。GitHub Copilot は月額 10 ドル。ローカルモデルは初回ダウンロード後**完全に無料**です。モデルはオープンソースで自由に使えます。

### オフラインで動作

飛行機の中？Wi-Fi のない山小屋？関係ありません。ローカルモデルは CPU と RAM のみで完全に動作します——インターネット接続は不要です。

---

## 前提条件

GPU やハイエンドワークステーションは必要ありません。最低要件は以下の通りです：

- **OS：** Windows 10/11、macOS 12+ または Linux
- **RAM：** 最低 8 GB（より大きなモデルには 16 GB 推奨）
- **ディスク容量：** アプリケーションと 1 つのモデル用に約 5 GB の空き容量
- **オプション：** 専用 GPU（NVIDIA/AMD）は推論を高速化しますが、**必須ではありません**

---

## ステップ 1：Ollama のダウンロードとインストール

**Ollama** は、1 つのコマンドで LLM をダウンロード、管理、実行できる軽量なランタイムです。どのプラットフォームでもインストールは簡単です。

### Windows

1. [ollama.com](https://ollama.com) にアクセスして **Download for Windows** をクリック。
2. インストーラーを実行——約 1 分で完了します。
3. インストール後、Ollama は自動的にバックグラウンドで実行されます。

### macOS

2 つの選択肢があります：

```bash
# オプション A：Homebrew（推奨）
brew install ollama

# オプション B：直接ダウンロード
# https://ollama.com にアクセスして .dmg をダウンロード
```

### Linux

1 つのコマンドですべて完了します：

```bash
curl -fsSL https://ollama.com/install.sh | sh
```

インストール後、動作を確認します：

```bash
ollama --version
```

ターミナルにバージョン番号が表示されるはずです。

---

## ステップ 2：最初のモデルを実行——魔法のコマンド

いよいよです。ターミナルを開いて入力してください：

```bash
ollama run llama3
```

これだけです。Ollama は初回実行時に **Llama 3 8B** モデル（約 4.7 GB）をダウンロードし、ターミナルで直接インタラクティブなチャットセッションを開始します：

```
>>> あなたは誰ですか？
私は Llama です。Meta によってトレーニングされた大規模言語モデルです。
今日は何をお手伝いしましょうか？

>>> 数が素数かどうかを判定する Python 関数を書いてください。
def is_prime(n):
    if n < 2:
        return False
    for i in range(2, int(n**0.5) + 1):
        if n % i == 0:
            return False
    return True
```

### 推論タスクには DeepSeek-R1 を試す

**DeepSeek-R1** は数学、論理、ステップバイステップの問題解決に優れています：

```bash
ollama run deepseek-r1
```

### その他の人気モデル

| モデル | コマンド | 最適な用途 |
|---|---|---|
| Llama 3 8B | `ollama run llama3` | 一般チャット、コーディング |
| DeepSeek-R1 8B | `ollama run deepseek-r1` | 数学、論理、推論 |
| Mistral 7B | `ollama run mistral` | 高速で効率的なオールラウンダー |
| Gemma 2 9B | `ollama run gemma2` | Google のオープンモデル |
| Qwen 2.5 7B | `ollama run qwen2.5` | 多言語タスク |

`ollama list` でダウンロード済みモデルを確認し、`ollama rm <モデル名>` でモデルを削除してディスク容量を解放できます。

---

## ステップ 3：Open WebUI でチャットインターフェースを追加（オプション）

ターミナルでも機能しますが、洗練された **ChatGPT 風のインターフェース** が欲しい場合は **Open WebUI** をインストールしてください。最速の方法は Docker です：

```bash
docker run -d -p 3000:8080 --add-host=host.docker.internal:host-gateway \
  -v open-webui:/app/backend/data --name open-webui \
  --restart always ghcr.io/open-webui/open-webui:main
```

次にブラウザで [http://localhost:3000](http://localhost:3000) を開きます。会話履歴、モデル切替、ファイルアップロードなどを備えた見慣れたチャットインターフェースが表示されます——すべてローカルの Ollama インスタンスに接続されています。

> **Docker がない場合は？** [Chatbox](https://chatboxai.app)（デスクトップアプリ）や [Ollama Web UI](https://github.com/ollama-webui/ollama-webui) など、Docker 不要の軽量フロントエンドもあります。

---

## ローカル AI vs. クラウド AI：完全比較

| 特徴 | ローカル AI（Ollama） | クラウド AI（ChatGPT、Claude） |
|---|---|---|
| **プライバシー** | データは PC から一切出ない | データはリモートサーバーに送信される |
| **コスト** | 完全無料 | プレミアム版は月額 20 ドル |
| **インターネット必要** | いいえ——完全オフラインで動作 | はい——常に |
| **速度** | ハードウェアに依存 | 高速（サーバー側 GPU） |
| **モデル品質** | 優秀（Llama 3、DeepSeek） | 優秀（GPT-4o、Claude） |
| **セットアップ** | 1 つのコマンド | アカウント作成 |
| **カスタマイズ** | 完全な制御、ファインチューニング | 制限あり |
| **データ保持** | すべてあなたが管理 | プロバイダーのポリシーが適用 |

**要点：** クラウドモデルは最も大規模なタスクでは生の能力で優位性がありますが、日常的なコーディング支援、ライティング、ブレインストーミング、Q&A には、ローカルモデルで**十分以上**です——しかも無料でプライベートです。

---

## まとめ

ローカル AI の実行は、高価な GPU を持つ研究者だけのニッチな趣味ではなくなりました。**Ollama** とオープンソースモデルのエコシステムのおかげで、モダンなノートパソコンを持つ誰もが 10 分以内にプライベートで無料、オフライン対応の AI アシスタントを手に入れることができます。

覚えておくコマンド：

```bash
# インストール（Linux）
curl -fsSL https://ollama.com/install.sh | sh

# モデルを実行
ollama run llama3

# モデル一覧を表示
ollama list
```

ぜひお試しください。ローカル LLM のスピードとプライバシーを体験すれば、クラウドに頼ることが少なくなるかもしれません。

> ローカル AI と一緒にコーディングしながら集中したいですか？[ZenFocus アンビエントミキサーとポモドーロタイマー](/ja/tools/zen-focus/)をお試しください——トラッキング一切なしでブラウザ上で完全に動作するもう一つのツールです。
