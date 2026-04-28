---
title: "Git Protocol: The Essential Command Reference"
description: "A tactical Git cheatsheet covering emergency fixes, GPG signing, branch operations, and advanced workflows. The commands every developer and hacker needs memorized."
date: 2026-02-10
tags: ["git", "cheatsheet", "version-control", "developer-tools"]
keywords: ["git commands cheatsheet", "git undo commit", "git gpg signing", "git branch commands", "git reset guide", "git rebase tutorial", "advanced git commands", "git for hackers"]
draft: false
schema_json: >
  {
    "@context": "https://schema.org",
    "@type": "TechArticle",
    "name": "Git Protocol: The Essential Command Reference",
    "description": "Comprehensive Git command cheatsheet covering emergency fixes, GPG signing, branch operations, and advanced workflows.",
    "proficiencyLevel": "Intermediate",
    "inLanguage": "en"
  }
---

## System Init

Every operation leaves a trace. Every commit is a checkpoint. Git is not just version control — it is the forensic backbone of every software project. This field manual contains the commands you will use daily and the ones that will save you when everything breaks.

Commands are organized by mission type. Execute with precision.

---

## Emergency Fixes

When a deploy goes wrong and the timeline needs rewriting.

### Undo the last commit (keep changes staged)

```bash
# Undo the last commit but keep your changes in the staging area
git reset --soft HEAD~1
```

### Undo the last commit (unstage changes)

```bash
# Undo the last commit and move changes back to the working directory
git reset --mixed HEAD~1
```

### Nuclear reset (destroy all local changes)

```bash
# WARNING: This permanently destroys all uncommitted work
git reset --hard HEAD~1
```

### Amend the last commit message

```bash
# Fix a typo in your last commit message without creating a new commit
git commit --amend -m "corrected commit message"
```

### Recover a deleted branch

```bash
# Find the lost commit hash in the reflog
git reflog

# Recreate the branch from the recovered hash
git checkout -b recovered-branch abc1234
```

### Revert a commit without rewriting history

```bash
# Create a new commit that undoes a specific commit (safe for shared branches)
git revert <commit-hash>
```

---

## Stealth Mode

Cryptographic signing and identity verification. Prove your commits are authentic.

### Configure GPG signing

```bash
# List your available GPG keys
gpg --list-secret-keys --keyid-format=long

# Tell Git which key to use
git config --global user.signingkey YOUR_KEY_ID

# Enable automatic signing for all commits
git config --global commit.gpgsign true
```

### Sign a single commit

```bash
# Manually sign a specific commit
git commit -S -m "signed: verified deployment"
```

### Verify commit signatures

```bash
# Check the signature on the last commit
git log --show-signature -1

# Verify signatures across the entire log
git log --pretty="format:%h %G? %aN %s"
```

### Sign tags for releases

```bash
# Create a signed release tag
git tag -s v1.0.0 -m "Release v1.0.0 - signed"

# Verify a signed tag
git tag -v v1.0.0
```

---

## Branch Operations

Tactical branch management for parallel development.

### Create and switch to a new branch

```bash
# Create a feature branch and switch to it in one command
git checkout -b feature/new-module
```

### List all branches (local and remote)

```bash
# Show all branches including remote tracking branches
git branch -a
```

### Delete a branch safely

```bash
# Delete a local branch (only if fully merged)
git branch -d feature/old-module

# Force delete a local branch (even if unmerged)
git branch -D feature/abandoned-experiment
```

### Delete a remote branch

```bash
# Remove a branch from the remote repository
git push origin --delete feature/old-module
```

### Rebase onto main (linear history)

```bash
# Reapply your branch commits on top of the latest main
git checkout feature/my-work
git rebase main
```

### Interactive rebase (squash, reorder, edit)

```bash
# Rewrite the last 3 commits interactively
git rebase -i HEAD~3
```

---

## Reconnaissance

Inspect the repository state before making decisions.

### View compact log with graph

```bash
# One-line log with branch graph visualization
git log --oneline --graph --all --decorate
```

### Show changes in the staging area

```bash
# Compare staged changes against the last commit
git diff --cached
```

### Blame a file (find who changed each line)

```bash
# Show author and commit for every line in a file
git blame path/to/file.py
```

### Search commit messages

```bash
# Find commits containing a specific keyword in the message
git log --grep="bugfix" --oneline
```

### Find which commit introduced a bug

```bash
# Binary search through commits to find the breaking change
git bisect start
git bisect bad          # Current commit is broken
git bisect good abc1234 # This old commit was working
# Git will checkout commits for you to test
```

---

## Stash Operations

Temporarily shelve work without committing.

### Stash current changes

```bash
# Save uncommitted changes to a temporary stack
git stash push -m "work in progress: auth module"
```

### List all stashes

```bash
# View all stashed entries
git stash list
```

### Apply and drop a stash

```bash
# Restore the most recent stash and remove it from the stack
git stash pop

# Restore a specific stash by index
git stash apply stash@{2}
```

### Create a branch from a stash

```bash
# Turn a stash into a proper feature branch
git stash branch feature/from-stash stash@{0}
```

---

## Advanced Protocols

Power commands for complex scenarios.

### Cherry-pick a commit from another branch

```bash
# Apply a specific commit from one branch to your current branch
git cherry-pick <commit-hash>
```

### Clean untracked files

```bash
# Preview what will be deleted
git clean -n

# Delete untracked files and directories
git clean -fd
```

### Create a patch file

```bash
# Export the last commit as a portable patch file
git format-patch -1 HEAD

# Apply a patch file
git am < patch-file.patch
```

### Shallow clone (save bandwidth)

```bash
# Clone only the latest commit (no full history)
git clone --depth 1 https://github.com/user/repo.git
```
