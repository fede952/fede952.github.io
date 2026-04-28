---
title: "Git Disaster Recovery: Undoing Mistakes & Fixing History"
description: "The emergency kit for developers. Learn how to undo commits, fix merge conflicts, recover deleted branches, and master git rebase vs merge."
date: 2026-02-13
tags: ["git", "cheatsheet", "devops", "version-control"]
keywords: ["git undo commit", "git reset hard vs soft", "recover deleted branch", "git rebase tutorial", "fix merge conflict", "git cherry-pick"]
draft: false
schema_json: >
  {
    "@context": "https://schema.org",
    "@type": "TechArticle",
    "name": "Git Disaster Recovery: Undoing Mistakes & Fixing History",
    "description": "The emergency kit for developers. Learn how to undo commits, fix merge conflicts, recover deleted branches, and master git rebase vs merge.",
    "proficiencyLevel": "Intermediate",
    "inLanguage": "en"
  }
---

## Undoing Changes

The three pillars of "I messed up": reset, revert, and restore. Each has a different scope and danger level.

### git restore — Discard Unstaged Changes

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

### git reset — Move HEAD Backward

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

> **--soft** keeps everything staged. **--mixed** unstages but keeps files. **--hard** destroys everything. When in doubt, use `--soft`.

### git revert — Undo a Commit Safely (Public History)

```bash
# Create a new commit that undoes a specific commit
git revert abc1234

# Revert without auto-committing (stage changes only)
git revert --no-commit abc1234

# Revert a merge commit (keep parent #1)
git revert -m 1 <merge-commit-hash>
```

> Use `revert` instead of `reset` on shared branches — it doesn't rewrite history.

---

## Rewriting History

For when your commit messages are embarrassing or your branch history is a mess.

### git commit --amend

```bash
# Change the last commit message
git commit --amend -m "better message"

# Add forgotten files to the last commit
git add forgotten-file.txt
git commit --amend --no-edit
```

### git rebase -i (Interactive Rebase)

```bash
# Rewrite the last 3 commits
git rebase -i HEAD~3
```

In the editor, you can:

| Command  | Effect                            |
|----------|-----------------------------------|
| `pick`   | Keep commit as-is                 |
| `reword` | Change commit message             |
| `edit`   | Stop to amend the commit          |
| `squash` | Merge into previous commit        |
| `fixup`  | Like squash, but discard message  |
| `drop`   | Delete the commit entirely        |

```bash
# Rebase current branch onto main (linear history)
git rebase main

# Continue after resolving conflicts
git rebase --continue

# Abort a rebase gone wrong
git rebase --abort
```

> **Rebase vs Merge:** Rebase creates linear history (cleaner logs). Merge preserves branch topology (safer for shared branches). Never rebase commits that others have pulled.

---

## Recovery

When everything is on fire, these commands are your fire extinguisher.

### git reflog — The Lifesaver

The reflog records every HEAD movement. Even after a hard reset, your commits are still there.

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

### git fsck — Find Dangling Objects

```bash
# Find unreachable commits and blobs
git fsck --unreachable

# Find lost commits specifically
git fsck --lost-found
# Results saved to .git/lost-found/
```

### Recover a Deleted Branch

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

## Common Disaster Scenarios

### "I committed to the wrong branch"

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

### "I need to stop tracking a file but keep it locally"

```bash
# Remove from git tracking but keep the file on disk
git rm --cached secret-config.env

# Add to .gitignore to prevent future tracking
echo "secret-config.env" >> .gitignore
git add .gitignore
git commit -m "stop tracking secret-config.env"
```

### "I need to undo a push"

```bash
# Safe way: revert the commit (creates new commit)
git revert abc1234
git push

# Nuclear option: force push (DANGEROUS on shared branches)
git reset --hard HEAD~1
git push --force-with-lease
```

### "My merge has conflicts everywhere"

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

### git cherry-pick — Grab Specific Commits

```bash
# Apply a single commit from another branch
git cherry-pick abc1234

# Apply multiple commits
git cherry-pick abc1234 def5678

# Cherry-pick without committing (stage only)
git cherry-pick --no-commit abc1234
```

---

## Quick Reference Table

| Situation | Command |
|-----------|---------|
| Undo last commit (keep changes) | `git reset --soft HEAD~1` |
| Undo last commit (delete changes) | `git reset --hard HEAD~1` |
| Undo a pushed commit | `git revert <hash>` |
| Discard file changes | `git restore <file>` |
| Unstage a file | `git restore --staged <file>` |
| Recover deleted branch | `git reflog` + `git branch name <hash>` |
| Fix last commit message | `git commit --amend -m "new msg"` |
| Squash last N commits | `git rebase -i HEAD~N` |
| Move commit to correct branch | `git reset --soft HEAD~1` + stash + switch |
| Stop tracking a file | `git rm --cached <file>` |
