---
title: "修复: fatal: refusing to merge unrelated histories"
description: "修复 Git 在 pull 或 merge 时出现的 'refusing to merge unrelated histories' 错误。了解为什么会发生以及如何安全地合并两个独立的仓库。"
date: 2026-02-11
tags: ["git", "debug", "devops", "version-control"]
keywords: ["refusing to merge unrelated histories", "git pull unrelated histories", "git merge unrelated histories", "allow unrelated histories", "fatal refusing to merge", "git pull origin main error", "git merge two repos", "git init push error", "github first commit merge", "git unrelated histories fix"]
draft: false
schema_json: >
  {
    "@context": "https://schema.org",
    "@type": "TechArticle",
    "name": "修复: fatal: refusing to merge unrelated histories",
    "description": "如何修复合并独立仓库时 Git 的 refusing to merge unrelated histories 错误。",
    "proficiencyLevel": "Beginner",
    "inLanguage": "zh-cn"
  }
---

## 错误信息

你尝试从远程仓库拉取或合并分支时，Git 拒绝了：

```
fatal: refusing to merge unrelated histories
```

这通常发生在你执行以下命令时：

```bash
git pull origin main
```

本地和远程仓库没有共同的祖先提交 — Git 将它们视为两个完全独立的项目，并拒绝自动合并。

---

## 快速修复

添加 `--allow-unrelated-histories` 标志来强制 Git 合并两个独立的历史记录：

```bash
# Pull and merge unrelated histories
git pull origin main --allow-unrelated-histories
```

或者如果你正在合并分支：

```bash
# Merge a branch with unrelated history
git merge other-branch --allow-unrelated-histories
```

Git 将尝试合并。如果有文件冲突，正常解决即可：

```bash
# Check which files conflict
git status

# After resolving conflicts in your editor
git add .
git commit -m "Merge unrelated histories"
```

---

## 为什么会发生

当两个 Git 仓库没有共同的提交历史时，就会出现此错误。最常见的场景：

### 场景 1：新仓库的 README 冲突

你使用 `git init` 创建了本地仓库并进行了一些提交。然后你在 GitHub 上创建了一个**包含 README.md**（或 `.gitignore` 或 `LICENSE`）的仓库。现在当你尝试拉取时，远程仓库有一个你本地仓库不知道的根提交。

```bash
# This is the classic cause:
mkdir my-project && cd my-project
git init
echo "hello" > app.py
git add . && git commit -m "first commit"
git remote add origin https://github.com/user/my-project.git
git pull origin main   # ERROR: unrelated histories
```

**预防措施：** 当创建新的 GitHub 仓库来推送现有本地项目时，创建远程仓库时**不要**初始化（不要添加 README、不要添加 .gitignore、不要添加许可证）。然后直接推送。

### 场景 2：合并两个独立的仓库

你想将两个独立的项目合并到一个仓库中。由于它们是独立创建的，它们有完全不同的提交树。

### 场景 3：重写的历史

有人在远程仓库上执行了 `git rebase` 或 `git filter-branch`，重写了根提交。远程的历史不再与你的本地副本共享祖先。

---

## 安全吗？

是的 — `--allow-unrelated-histories` 只是告诉 Git 即使两个分支没有共同基础也继续合并。它不会删除、覆盖或变基任何内容。如果有冲突的文件，Git 会将它们标记为冲突，让你手动解决，与普通合并完全相同。

该标志在 **Git 2.9**（2016 年 6 月）中添加。在该版本之前，Git 默认允许不相关的合并。

---

## 相关资源

通过我们的 [Git Protocol Cheatsheet](/cheatsheets/git-commands-for-hackers/) 掌握高级合并、变基和冲突解决 — 开发者需要的每个 Git 命令，按工作流程组织。
