---
title: "استعادة كوارث Git: التراجع عن الأخطاء وإصلاح السجل"
description: "مجموعة الطوارئ للمطورين. تعلم كيفية التراجع عن الكوميتات، حل تعارضات الدمج، استعادة الفروع المحذوفة، وإتقان git rebase مقابل merge."
date: 2026-02-13
tags: ["git", "cheatsheet", "devops", "version-control"]
keywords: ["git undo commit", "git reset hard vs soft", "recover deleted branch", "git rebase tutorial", "fix merge conflict", "git cherry-pick"]
draft: false
schema_json: >
  {
    "@context": "https://schema.org",
    "@type": "TechArticle",
    "name": "استعادة كوارث Git: التراجع عن الأخطاء وإصلاح السجل",
    "description": "مجموعة الطوارئ للمطورين. تعلم كيفية التراجع عن الكوميتات، حل تعارضات الدمج، استعادة الفروع المحذوفة، وإتقان git rebase مقابل merge.",
    "proficiencyLevel": "Intermediate",
    "inLanguage": "ar"
  }
---

## التراجع عن التغييرات

الركائز الثلاث لـ "لقد أخطأت": reset وrevert وrestore. لكل منها نطاق مختلف ومستوى خطورة مختلف.

### git restore — تجاهل التغييرات غير المُرحَّلة

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

### git reset — تحريك HEAD للخلف

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

> **--soft** يُبقي كل شيء مُرحَّلاً. **--mixed** يُلغي الترحيل لكن يحتفظ بالملفات. **--hard** يُدمّر كل شيء. عند الشك، استخدم `--soft`.

### git revert — التراجع عن كوميت بأمان (السجل العام)

```bash
# Create a new commit that undoes a specific commit
git revert abc1234

# Revert without auto-committing (stage changes only)
git revert --no-commit abc1234

# Revert a merge commit (keep parent #1)
git revert -m 1 <merge-commit-hash>
```

> استخدم `revert` بدلاً من `reset` على الفروع المشتركة — فهو لا يُعيد كتابة السجل.

---

## إعادة كتابة السجل

عندما تكون رسائل الكوميت محرجة أو سجل الفرع فوضوياً.

### git commit --amend

```bash
# Change the last commit message
git commit --amend -m "better message"

# Add forgotten files to the last commit
git add forgotten-file.txt
git commit --amend --no-edit
```

### git rebase -i (إعادة التأسيس التفاعلية)

```bash
# Rewrite the last 3 commits
git rebase -i HEAD~3
```

في المحرر، يمكنك:

| الأمر    | التأثير                           |
|----------|-----------------------------------|
| `pick`   | الاحتفاظ بالكوميت كما هو         |
| `reword` | تغيير رسالة الكوميت              |
| `edit`   | التوقف لتعديل الكوميت            |
| `squash` | دمجه مع الكوميت السابق           |
| `fixup`  | مثل squash، لكن بتجاهل الرسالة   |
| `drop`   | حذف الكوميت بالكامل              |

```bash
# Rebase current branch onto main (linear history)
git rebase main

# Continue after resolving conflicts
git rebase --continue

# Abort a rebase gone wrong
git rebase --abort
```

> **Rebase مقابل Merge:** يُنشئ Rebase سجلاً خطياً (سجلات أنظف). يحافظ Merge على هيكل الفروع (أكثر أماناً للفروع المشتركة). لا تقم أبداً بعمل rebase لكوميتات سحبها آخرون.

---

## الاستعادة

عندما يكون كل شيء مشتعلاً، هذه الأوامر هي طفاية الحريق.

### git reflog — طوق النجاة

يُسجّل reflog كل حركة لـ HEAD. حتى بعد hard reset، كوميتاتك لا تزال موجودة.

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

### git fsck — البحث عن الكائنات المعلّقة

```bash
# Find unreachable commits and blobs
git fsck --unreachable

# Find lost commits specifically
git fsck --lost-found
# Results saved to .git/lost-found/
```

### استعادة فرع محذوف

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

## سيناريوهات الكوارث الشائعة

### "عملت كوميت على الفرع الخطأ"

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

### "أريد إيقاف تتبع ملف مع الاحتفاظ به محلياً"

```bash
# Remove from git tracking but keep the file on disk
git rm --cached secret-config.env

# Add to .gitignore to prevent future tracking
echo "secret-config.env" >> .gitignore
git add .gitignore
git commit -m "stop tracking secret-config.env"
```

### "أحتاج التراجع عن push"

```bash
# Safe way: revert the commit (creates new commit)
git revert abc1234
git push

# Nuclear option: force push (DANGEROUS on shared branches)
git reset --hard HEAD~1
git push --force-with-lease
```

### "الدمج فيه تعارضات في كل مكان"

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

### git cherry-pick — جلب كوميتات محددة

```bash
# Apply a single commit from another branch
git cherry-pick abc1234

# Apply multiple commits
git cherry-pick abc1234 def5678

# Cherry-pick without committing (stage only)
git cherry-pick --no-commit abc1234
```

---

## جدول مرجعي سريع

| الحالة | الأمر |
|--------|-------|
| التراجع عن آخر كوميت (الاحتفاظ بالتغييرات) | `git reset --soft HEAD~1` |
| التراجع عن آخر كوميت (حذف التغييرات) | `git reset --hard HEAD~1` |
| التراجع عن كوميت تم دفعه | `git revert <hash>` |
| تجاهل تغييرات ملف | `git restore <file>` |
| إلغاء ترحيل ملف | `git restore --staged <file>` |
| استعادة فرع محذوف | `git reflog` + `git branch name <hash>` |
| إصلاح رسالة آخر كوميت | `git commit --amend -m "new msg"` |
| دمج آخر N كوميتات | `git rebase -i HEAD~N` |
| نقل كوميت للفرع الصحيح | `git reset --soft HEAD~1` + stash + switch |
| إيقاف تتبع ملف | `git rm --cached <file>` |
