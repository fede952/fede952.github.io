---
title: "修正: fatal: refusing to merge unrelated histories"
description: "pullやmerge時に発生するGitの'refusing to merge unrelated histories'エラーを修正します。なぜ発生するのか、そして2つの独立したリポジトリを安全に統合する方法を理解しましょう。"
date: 2026-02-11
tags: ["git", "debug", "devops", "version-control"]
keywords: ["refusing to merge unrelated histories", "git pull unrelated histories", "git merge unrelated histories", "allow unrelated histories", "fatal refusing to merge", "git pull origin main error", "git merge two repos", "git init push error", "github first commit merge", "git unrelated histories fix"]
draft: false
schema_json: >
  {
    "@context": "https://schema.org",
    "@type": "TechArticle",
    "name": "修正: fatal: refusing to merge unrelated histories",
    "description": "独立したリポジトリを統合する際のGitエラー refusing to merge unrelated histories の修正方法。",
    "proficiencyLevel": "Beginner",
    "inLanguage": "ja"
  }
---

## エラー内容

リモートリポジトリからpullしたり、ブランチをマージしようとすると、Gitが拒否します：

```
fatal: refusing to merge unrelated histories
```

これは通常、以下を実行したときに発生します：

```bash
git pull origin main
```

ローカルとリモートのリポジトリに共通の祖先コミットがない場合 — Gitはそれらを2つの完全に別々のプロジェクトと見なし、自動的に統合することを拒否します。

---

## 簡単な修正方法

`--allow-unrelated-histories`フラグを追加して、Gitに2つの独立した履歴のマージを強制します：

```bash
# Pull and merge unrelated histories
git pull origin main --allow-unrelated-histories
```

または、ブランチをマージする場合：

```bash
# Merge a branch with unrelated history
git merge other-branch --allow-unrelated-histories
```

Gitはマージを試みます。ファイルの競合がある場合は、通常通り解決してください：

```bash
# Check which files conflict
git status

# After resolving conflicts in your editor
git add .
git commit -m "Merge unrelated histories"
```

---

## なぜ発生するのか

このエラーは、2つのGitリポジトリが共通のコミット履歴を共有していない場合に発生します。最も一般的なシナリオ：

### シナリオ1：READMEの競合がある新しいリポジトリ

`git init`でローカルリポジトリを作成し、いくつかのコミットを行いました。その後、GitHubで**README.md**（または`.gitignore`や`LICENSE`）**付きの**リポジトリを作成しました。pullしようとすると、リモートにはローカルリポジトリが知らないルートコミットがあります。

```bash
# This is the classic cause:
mkdir my-project && cd my-project
git init
echo "hello" > app.py
git add . && git commit -m "first commit"
git remote add origin https://github.com/user/my-project.git
git pull origin main   # ERROR: unrelated histories
```

**予防策：** 既存のローカルプロジェクトをpushするために新しいGitHubリポジトリを作成する場合、リモートリポジトリを初期化**せずに**作成してください（README なし、.gitignore なし、ライセンスなし）。その後、直接pushしてください。

### シナリオ2：2つの独立したリポジトリの統合

2つの別々のプロジェクトを1つのリポジトリに統合したい場合。独立して作成されたため、完全に異なるコミットツリーを持っています。

### シナリオ3：書き換えられた履歴

誰かがリモートで`git rebase`や`git filter-branch`を実行し、ルートコミットが書き換えられました。リモートの履歴はローカルコピーと共通の祖先を共有しなくなりました。

---

## 安全ですか？

はい — `--allow-unrelated-histories`は、2つのブランチに共通のベースがなくてもマージを続行するようGitに指示するだけです。何も削除、上書き、リベースしません。競合するファイルがある場合、Gitはそれらを競合としてマークし、通常のマージと同じように手動で解決できるようにします。

このフラグは**Git 2.9**（2016年6月）で追加されました。そのバージョン以前は、Gitはデフォルトで無関係なマージを許可していました。

---

## 関連リソース

高度なマージ、リベース、競合解決を[Git Protocol Cheatsheet](/cheatsheets/git-commands-for-hackers/)でマスターしましょう — 開発者が必要とするすべてのGitコマンドをワークフロー別に整理しています。
