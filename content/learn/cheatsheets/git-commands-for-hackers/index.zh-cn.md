---
title: "Git协议：必备命令参考"
description: "涵盖紧急修复、GPG签名、分支操作和高级工作流的战术性Git速查表。每个开发者和黑客都需要记住的命令。"
date: 2026-02-10
tags: ["git", "cheatsheet", "version-control", "developer-tools"]
keywords: ["git命令速查表", "git撤销提交", "git gpg签名", "git分支命令", "git reset指南", "git rebase教程", "高级git命令", "黑客的git"]
draft: false
schema_json: >
  {
    "@context": "https://schema.org",
    "@type": "TechArticle",
    "name": "Git协议：必备命令参考",
    "description": "全面的Git命令速查表，涵盖紧急修复、GPG签名、分支操作和高级工作流。",
    "proficiencyLevel": "Intermediate",
    "inLanguage": "zh-CN"
  }
---

## $ System_Init

每个操作都会留下痕迹。每个提交都是一个检查点。Git不仅仅是版本控制——它是每个软件项目的取证支柱。这本现场手册包含你每天都会使用的命令，以及在一切崩溃时拯救你的命令。

命令按任务类型组织。精确执行。

---

## $ Emergency_Fixes

当部署出错且需要重写时间线时。

### 撤销最后一次提交（保持更改在暂存区）

```bash
# 撤销最后一次提交但将更改保留在暂存区
git reset --soft HEAD~1
```

### 撤销最后一次提交（取消暂存更改）

```bash
# 撤销最后一次提交并将更改移回工作目录
git reset --mixed HEAD~1
```

### 核重置（销毁所有本地更改）

```bash
# 警告：这会永久销毁所有未提交的工作
git reset --hard HEAD~1
```

### 修改最后一次提交消息

```bash
# 修复最后一次提交消息中的错字而不创建新提交
git commit --amend -m "更正的提交消息"
```

### 恢复已删除的分支

```bash
# 在reflog中查找丢失的提交哈希
git reflog

# 从恢复的哈希重新创建分支
git checkout -b recovered-branch abc1234
```

### 还原提交而不重写历史

```bash
# 创建一个新提交来撤销特定提交（对共享分支安全）
git revert <commit-hash>
```

---

## $ Stealth_Mode

加密签名和身份验证。证明你的提交是真实的。

### 配置GPG签名

```bash
# 列出可用的GPG密钥
gpg --list-secret-keys --keyid-format=long

# 告诉Git使用哪个密钥
git config --global user.signingkey YOUR_KEY_ID

# 为所有提交启用自动签名
git config --global commit.gpgsign true
```

### 签名单个提交

```bash
# 手动签名特定提交
git commit -S -m "signed: verified deployment"
```

### 验证提交签名

```bash
# 检查最后一次提交的签名
git log --show-signature -1

# 验证整个日志中的签名
git log --pretty="format:%h %G? %aN %s"
```

### 为发布签名标签

```bash
# 创建已签名的发布标签
git tag -s v1.0.0 -m "Release v1.0.0 - signed"

# 验证已签名的标签
git tag -v v1.0.0
```

---

## $ Branch_Operations

并行开发的战术性分支管理。

### 创建并切换到新分支

```bash
# 创建功能分支并在一个命令中切换到它
git checkout -b feature/new-module
```

### 列出所有分支（本地和远程）

```bash
# 显示所有分支，包括远程跟踪分支
git branch -a
```

### 安全删除分支

```bash
# 删除本地分支（仅当完全合并时）
git branch -d feature/old-module

# 强制删除本地分支（即使未合并）
git branch -D feature/abandoned-experiment
```

### 删除远程分支

```bash
# 从远程仓库中删除分支
git push origin --delete feature/old-module
```

### 变基到main（线性历史）

```bash
# 将分支提交重新应用到最新的main之上
git checkout feature/my-work
git rebase main
```

### 交互式变基（压缩、重排序、编辑）

```bash
# 交互式重写最后3次提交
git rebase -i HEAD~3
```

---

## $ Reconnaissance

在做出决定之前检查仓库状态。

### 查看带图形的紧凑日志

```bash
# 带有分支图形可视化的单行日志
git log --oneline --graph --all --decorate
```

### 显示暂存区中的更改

```bash
# 将暂存的更改与最后一次提交进行比较
git diff --cached
```

### 追溯文件（查找谁更改了每一行）

```bash
# 显示文件中每一行的作者和提交
git blame path/to/file.py
```

### 搜索提交消息

```bash
# 查找消息中包含特定关键字的提交
git log --grep="bugfix" --oneline
```

### 查找引入错误的提交

```bash
# 通过二分搜索提交找到破坏代码的更改
git bisect start
git bisect bad          # 当前提交已损坏
git bisect good abc1234 # 这个旧提交是好的
# Git会检出提交供你测试
```

---

## $ Stash_Operations

在不提交的情况下临时搁置工作。

### 暂存当前更改

```bash
# 将未提交的更改保存到临时堆栈
git stash push -m "work in progress: auth module"
```

### 列出所有暂存

```bash
# 查看所有暂存条目
git stash list
```

### 应用并删除暂存

```bash
# 恢复最近的暂存并将其从堆栈中移除
git stash pop

# 按索引恢复特定暂存
git stash apply stash@{2}
```

### 从暂存创建分支

```bash
# 将暂存转换为适当的功能分支
git stash branch feature/from-stash stash@{0}
```

---

## $ Advanced_Protocols

复杂场景的强大命令。

### 从另一个分支拣选提交

```bash
# 将一个分支的特定提交应用到当前分支
git cherry-pick <commit-hash>
```

### 清理未跟踪的文件

```bash
# 预览将被删除的内容
git clean -n

# 删除未跟踪的文件和目录
git clean -fd
```

### 创建补丁文件

```bash
# 将最后一次提交导出为可移植的补丁文件
git format-patch -1 HEAD

# 应用补丁文件
git am < patch-file.patch
```

### 浅克隆（节省带宽）

```bash
# 仅克隆最新提交（无完整历史）
git clone --depth 1 https://github.com/user/repo.git
```
