---
title: "Git 災害復旧：ミスの取り消しと履歴の修正"
description: "開発者のための緊急キット。コミットの取り消し、マージコンフリクトの解決、削除されたブランチの復旧、git rebase vs merge の使い分けを学ぼう。"
date: 2026-02-13
tags: ["git", "cheatsheet", "devops", "version-control"]
keywords: ["git undo commit", "git reset hard vs soft", "recover deleted branch", "git rebase tutorial", "fix merge conflict", "git cherry-pick"]
draft: false
schema_json: >
  {
    "@context": "https://schema.org",
    "@type": "TechArticle",
    "name": "Git 災害復旧：ミスの取り消しと履歴の修正",
    "description": "開発者のための緊急キット。コミットの取り消し、マージコンフリクトの解決、削除されたブランチの復旧、git rebase vs merge の使い分けを学ぼう。",
    "proficiencyLevel": "Intermediate",
    "inLanguage": "ja"
  }
---

## 変更の取り消し

「やらかした」ときの三本柱：reset、revert、restore。それぞれスコープと危険度が異なる。

### git restore — ステージされていない変更を破棄する

```bash
# 単一ファイルの変更を破棄する（作業ディレクトリのみ）
git restore file.txt

# すべてのステージされていない変更を破棄する
git restore .

# ファイルをアンステージする（作業ディレクトリの変更は保持）
git restore --staged file.txt

# 特定のコミットのバージョンにファイルを復元する
git restore --source=abc1234 file.txt
```

### git reset — HEADを後ろに移動する

```bash
# ソフトリセット：コミットを取り消し、変更はステージされたまま
git reset --soft HEAD~1

# ミックスドリセット（デフォルト）：コミットを取り消し、アンステージするがファイルは保持
git reset HEAD~1

# ハードリセット：コミットを取り消し、すべての変更を完全に削除
git reset --hard HEAD~1

# 特定のコミットにリセット
git reset --hard abc1234
```

> **--soft** はすべてをステージされた状態で保持する。**--mixed** はアンステージするがファイルは保持する。**--hard** はすべてを破壊する。迷ったら `--soft` を使おう。

### git revert — 安全にコミットを取り消す（公開履歴向け）

```bash
# 特定のコミットを取り消す新しいコミットを作成
git revert abc1234

# 自動コミットなしで取り消す（変更をステージするだけ）
git revert --no-commit abc1234

# マージコミットを取り消す（親#1を保持）
git revert -m 1 <merge-commit-hash>
```

> 共有ブランチでは `reset` の代わりに `revert` を使おう — 履歴を書き換えないため安全だ。

---

## 履歴の書き換え

コミットメッセージが恥ずかしい場合や、ブランチ履歴がぐちゃぐちゃな場合に。

### git commit --amend

```bash
# 最後のコミットメッセージを変更する
git commit --amend -m "better message"

# 忘れたファイルを最後のコミットに追加する
git add forgotten-file.txt
git commit --amend --no-edit
```

### git rebase -i（インタラクティブリベース）

```bash
# 最後の3つのコミットを書き換える
git rebase -i HEAD~3
```

エディタで以下の操作ができる：

| コマンド | 効果 |
|----------|------|
| `pick`   | コミットをそのまま残す |
| `reword` | コミットメッセージを変更する |
| `edit`   | コミットを修正するために一時停止する |
| `squash` | 前のコミットに統合する |
| `fixup`  | squashと同じだがメッセージは破棄する |
| `drop`   | コミットを完全に削除する |

```bash
# 現在のブランチをmainにリベースする（直線的な履歴）
git rebase main

# コンフリクト解決後に続行する
git rebase --continue

# 失敗したリベースを中止する
git rebase --abort
```

> **Rebase vs Merge：** Rebaseは直線的な履歴を作る（ログがきれいになる）。Mergeはブランチのトポロジーを保持する（共有ブランチではより安全）。他の人がプルしたコミットは絶対にリベースしてはいけない。

---

## リカバリ

すべてが炎上しているとき、これらのコマンドが消火器になる。

### git reflog — 命綱

reflogはすべてのHEADの移動を記録している。ハードリセットの後でもコミットはまだそこにある。

```bash
# reflogを表示する（最近のすべてのHEAD位置）
git reflog

# 出力例：
# abc1234 HEAD@{0}: reset: moving to HEAD~3
# def5678 HEAD@{1}: commit: add feature X
# 9ab0123 HEAD@{2}: commit: fix login bug

# reflogエントリにリセットして復旧する
git reset --hard HEAD@{1}

# または失われたコミットをcherry-pickする
git cherry-pick def5678
```

### git fsck — ぶら下がりオブジェクトを見つける

```bash
# 到達不能なコミットとblobを見つける
git fsck --unreachable

# 失われたコミットを具体的に見つける
git fsck --lost-found
# 結果は .git/lost-found/ に保存される
```

### 削除されたブランチの復旧

```bash
# ステップ1：削除されたブランチの最後のコミットを見つける
git reflog | grep "branch-name"
# またはコミットメッセージで検索する
git reflog | grep "feature I was working on"

# ステップ2：そのコミットでブランチを再作成する
git branch recovered-branch abc1234

# 代替方法：一発で見つけて復元する
git checkout -b recovered-branch HEAD@{5}
```

---

## よくある災害シナリオ

### 「間違ったブランチにコミットしてしまった」

```bash
# ステップ1：コミットハッシュを控える
git log --oneline -1
# abc1234 accidental commit

# ステップ2：間違ったブランチでコミットを取り消す（変更は保持）
git reset --soft HEAD~1

# ステップ3：スタッシュして、切り替えて、適用する
git stash
git checkout correct-branch
git stash pop
git add . && git commit -m "feature in the right place"
```

### 「ファイルの追跡を停止したいがローカルには残したい」

```bash
# gitの追跡から外すがディスク上のファイルは残す
git rm --cached secret-config.env

# .gitignoreに追加して将来の追跡を防ぐ
echo "secret-config.env" >> .gitignore
git add .gitignore
git commit -m "stop tracking secret-config.env"
```

### 「プッシュを取り消したい」

```bash
# 安全な方法：コミットをrevertする（新しいコミットが作成される）
git revert abc1234
git push

# 最終手段：強制プッシュ（共有ブランチでは危険）
git reset --hard HEAD~1
git push --force-with-lease
```

### 「マージでコンフリクトだらけ」

```bash
# コンフリクトのあるファイルを確認する
git status

# コンフリクトのあるファイルでコンフリクトマーカーを探す：
# <<<<<<< HEAD
# your changes
# =======
# their changes
# >>>>>>> branch-name

# すべてのコンフリクトを解決した後：
git add .
git commit

# またはマージを完全に中止する
git merge --abort
```

### git cherry-pick — 特定のコミットを取り込む

```bash
# 別のブランチから単一のコミットを適用する
git cherry-pick abc1234

# 複数のコミットを適用する
git cherry-pick abc1234 def5678

# コミットせずにcherry-pickする（ステージするだけ）
git cherry-pick --no-commit abc1234
```

---

## クイックリファレンス表

| 状況 | コマンド |
|------|---------|
| 最後のコミットを取り消す（変更を保持） | `git reset --soft HEAD~1` |
| 最後のコミットを取り消す（変更を削除） | `git reset --hard HEAD~1` |
| プッシュ済みのコミットを取り消す | `git revert <hash>` |
| ファイルの変更を破棄する | `git restore <file>` |
| ファイルをアンステージする | `git restore --staged <file>` |
| 削除されたブランチを復旧する | `git reflog` + `git branch name <hash>` |
| 最後のコミットメッセージを修正する | `git commit --amend -m "new msg"` |
| 最後のN個のコミットをまとめる | `git rebase -i HEAD~N` |
| コミットを正しいブランチに移す | `git reset --soft HEAD~1` + stash + switch |
| ファイルの追跡を停止する | `git rm --cached <file>` |
