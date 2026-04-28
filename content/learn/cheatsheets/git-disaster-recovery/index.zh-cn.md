---
title: "Git 灾难恢复：撤销错误与修复历史"
description: "开发者的急救工具包。学习如何撤销提交、解决合并冲突、恢复已删除的分支，以及掌握 git rebase 与 merge 的区别。"
date: 2026-02-13
tags: ["git", "cheatsheet", "devops", "version-control"]
keywords: ["git undo commit", "git reset hard vs soft", "recover deleted branch", "git rebase tutorial", "fix merge conflict", "git cherry-pick"]
draft: false
schema_json: >
  {
    "@context": "https://schema.org",
    "@type": "TechArticle",
    "name": "Git 灾难恢复：撤销错误与修复历史",
    "description": "开发者的急救工具包。学习如何撤销提交、解决合并冲突、恢复已删除的分支，以及掌握 git rebase 与 merge 的区别。",
    "proficiencyLevel": "Intermediate",
    "inLanguage": "zh-CN"
  }
---

## 撤销更改

"我搞砸了"的三大支柱：reset、revert 和 restore。每个命令的作用范围和危险等级各不相同。

### git restore — 丢弃未暂存的更改

```bash
# Discard changes in a single file (working directory only)
git restore file.txt

# Discard ALL unstaged changes
git restore .

# Unstage a file (keep changes in working directory)
git restore --staged file.txt

# Restore a file to a specific commit's version
git restore --source=abc1234 file.txt
```

### git reset — 将 HEAD 向后移动

```bash
# Soft reset: undo commit, keep changes staged
git reset --soft HEAD~1

# Mixed reset (default): undo commit, unstage changes, keep files
git reset HEAD~1

# Hard reset: undo commit, DELETE all changes permanently
git reset --hard HEAD~1

# Reset to a specific commit
git reset --hard abc1234
```

> **--soft** 保留所有暂存的更改。**--mixed** 取消暂存但保留文件。**--hard** 销毁一切。拿不准时，用 `--soft`。

### git revert — 安全地撤销提交（公共历史）

```bash
# Create a new commit that undoes a specific commit
git revert abc1234

# Revert without auto-committing (stage changes only)
git revert --no-commit abc1234

# Revert a merge commit (keep parent #1)
git revert -m 1 <merge-commit-hash>
```

> 在共享分支上使用 `revert` 而不是 `reset` — 它不会重写历史。

---

## 重写历史

当你的提交信息令人尴尬或分支历史一团糟时使用。

### git commit --amend

```bash
# Change the last commit message
git commit --amend -m "better message"

# Add forgotten files to the last commit
git add forgotten-file.txt
git commit --amend --no-edit
```

### git rebase -i（交互式变基）

```bash
# Rewrite the last 3 commits
git rebase -i HEAD~3
```

在编辑器中，你可以执行以下操作：

| 命令     | 效果                              |
|----------|-----------------------------------|
| `pick`   | 保留提交原样                      |
| `reword` | 修改提交信息                      |
| `edit`   | 停下来修改提交                    |
| `squash` | 合并到上一个提交                  |
| `fixup`  | 类似 squash，但丢弃信息           |
| `drop`   | 完全删除该提交                    |

```bash
# Rebase current branch onto main (linear history)
git rebase main

# Continue after resolving conflicts
git rebase --continue

# Abort a rebase gone wrong
git rebase --abort
```

> **Rebase vs Merge：** Rebase 创建线性历史（更清晰的日志）。Merge 保留分支拓扑结构（对共享分支更安全）。永远不要对别人已经拉取的提交进行 rebase。

---

## 恢复

当一切都着火时，这些命令就是你的灭火器。

### git reflog — 救命稻草

reflog 记录每一次 HEAD 的移动。即使在硬重置之后，你的提交仍然存在。

```bash
# View the reflog (all recent HEAD positions)
git reflog

# Example output:
# abc1234 HEAD@{0}: reset: moving to HEAD~3
# def5678 HEAD@{1}: commit: add feature X
# 9ab0123 HEAD@{2}: commit: fix login bug

# Recover by resetting to a reflog entry
git reset --hard HEAD@{1}

# Or cherry-pick a lost commit
git cherry-pick def5678
```

### git fsck — 查找悬空对象

```bash
# Find unreachable commits and blobs
git fsck --unreachable

# Find lost commits specifically
git fsck --lost-found
# Results saved to .git/lost-found/
```

### 恢复已删除的分支

```bash
# Step 1: find the last commit of the deleted branch
git reflog | grep "branch-name"
# Or search for the commit message
git reflog | grep "feature I was working on"

# Step 2: recreate the branch at that commit
git branch recovered-branch abc1234

# Alternative: find and restore in one shot
git checkout -b recovered-branch HEAD@{5}
```

---

## 常见灾难场景

### "我提交到了错误的分支"

```bash
# Step 1: Note the commit hash
git log --oneline -1
# abc1234 accidental commit

# Step 2: Undo the commit on the wrong branch (keep changes)
git reset --soft HEAD~1

# Step 3: Stash, switch, and apply
git stash
git checkout correct-branch
git stash pop
git add . && git commit -m "feature in the right place"
```

### "我需要停止跟踪一个文件但在本地保留它"

```bash
# Remove from git tracking but keep the file on disk
git rm --cached secret-config.env

# Add to .gitignore to prevent future tracking
echo "secret-config.env" >> .gitignore
git add .gitignore
git commit -m "stop tracking secret-config.env"
```

### "我需要撤销一次推送"

```bash
# Safe way: revert the commit (creates new commit)
git revert abc1234
git push

# Nuclear option: force push (DANGEROUS on shared branches)
git reset --hard HEAD~1
git push --force-with-lease
```

### "我的合并到处都是冲突"

```bash
# See which files have conflicts
git status

# For each conflicted file, look for conflict markers:
# <<<<<<< HEAD
# your changes
# =======
# their changes
# >>>>>>> branch-name

# After resolving all conflicts:
git add .
git commit

# Or abort the merge entirely
git merge --abort
```

### git cherry-pick — 抓取特定提交

```bash
# Apply a single commit from another branch
git cherry-pick abc1234

# Apply multiple commits
git cherry-pick abc1234 def5678

# Cherry-pick without committing (stage only)
git cherry-pick --no-commit abc1234
```

---

## 快速参考表

| 场景 | 命令 |
|------|------|
| 撤销上次提交（保留更改） | `git reset --soft HEAD~1` |
| 撤销上次提交（删除更改） | `git reset --hard HEAD~1` |
| 撤销已推送的提交 | `git revert <hash>` |
| 丢弃文件更改 | `git restore <file>` |
| 取消暂存文件 | `git restore --staged <file>` |
| 恢复已删除的分支 | `git reflog` + `git branch name <hash>` |
| 修改上次提交信息 | `git commit --amend -m "new msg"` |
| 压缩最近 N 次提交 | `git rebase -i HEAD~N` |
| 将提交移到正确的分支 | `git reset --soft HEAD~1` + stash + switch |
| 停止跟踪文件 | `git rm --cached <file>` |
