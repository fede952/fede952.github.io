---
title: "FIX: fatal: refusing to merge unrelated histories"
description: "Fix Git's 'refusing to merge unrelated histories' error when pulling or merging. Understand why it happens and how to safely combine two independent repositories."
date: 2026-02-11
tags: ["git", "debug", "devops", "version-control"]
keywords: ["refusing to merge unrelated histories", "git pull unrelated histories", "git merge unrelated histories", "allow unrelated histories", "fatal refusing to merge", "git pull origin main error", "git merge two repos", "git init push error", "github first commit merge", "git unrelated histories fix"]
draft: false
schema_json: >
  {
    "@context": "https://schema.org",
    "@type": "TechArticle",
    "name": "FIX: fatal: refusing to merge unrelated histories",
    "description": "How to fix Git's refusing to merge unrelated histories error when combining independent repositories.",
    "proficiencyLevel": "Beginner",
    "inLanguage": "en"
  }
---

## The Error

You try to pull from a remote repository or merge a branch and Git refuses:

```
fatal: refusing to merge unrelated histories
```

This typically happens when you run:

```bash
git pull origin main
```

And the local and remote repositories have no common ancestor commit — Git sees them as two completely separate projects and refuses to combine them automatically.

---

## The Quick Fix

Add the `--allow-unrelated-histories` flag to force Git to merge the two independent histories:

```bash
# Pull and merge unrelated histories
git pull origin main --allow-unrelated-histories
```

Or if you are merging a branch:

```bash
# Merge a branch with unrelated history
git merge other-branch --allow-unrelated-histories
```

Git will attempt the merge. If there are file conflicts, resolve them normally:

```bash
# Check which files conflict
git status

# After resolving conflicts in your editor
git add .
git commit -m "Merge unrelated histories"
```

---

## Why This Happens

This error occurs when two Git repositories share no common commit history. The most common scenarios:

### Scenario 1: New repo with a README conflict

You created a local repository with `git init` and made some commits. Then you created a GitHub repo **with a README.md** (or `.gitignore` or `LICENSE`). Now when you try to pull, the remote has a root commit that your local repo knows nothing about.

```bash
# This is the classic cause:
mkdir my-project && cd my-project
git init
echo "hello" > app.py
git add . && git commit -m "first commit"
git remote add origin https://github.com/user/my-project.git
git pull origin main   # ERROR: unrelated histories
```

**Prevention:** When creating a new GitHub repo to push an existing local project, create the remote repo **without** initializing it (no README, no .gitignore, no license). Then push directly.

### Scenario 2: Merging two independent repositories

You want to combine two separate projects into a single repository. Since they were created independently, they have completely different commit trees.

### Scenario 3: Rewritten history

Someone ran `git rebase` or `git filter-branch` on the remote, which rewrote the root commits. The remote's history no longer shares an ancestor with your local copy.

---

## Is It Safe?

Yes — `--allow-unrelated-histories` simply tells Git to proceed with the merge even though the two branches have no common base. It does not delete, overwrite, or rebase anything. If there are conflicting files, Git will mark them as conflicts and let you resolve them manually, exactly like a normal merge.

The flag was added in **Git 2.9** (June 2016). Before that version, Git allowed unrelated merges by default.

---

## Related Resources

Master advanced merges, rebases, and conflict resolution with our [Git Protocol Cheatsheet](/cheatsheets/git-commands-for-hackers/) — every Git command a developer needs, organized by workflow.
