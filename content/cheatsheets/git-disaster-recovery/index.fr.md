---
title: "Git Disaster Recovery : Annuler les Erreurs et Corriger l'Historique"
description: "Le kit d'urgence pour developpeurs. Apprenez a annuler des commits, resoudre des conflits de merge, recuperer des branches supprimees et maitriser git rebase vs merge."
date: 2026-02-13
tags: ["git", "cheatsheet", "devops", "version-control"]
keywords: ["git undo commit", "git reset hard vs soft", "recover deleted branch", "git rebase tutorial", "fix merge conflict", "git cherry-pick"]
draft: false
schema_json: >
  {
    "@context": "https://schema.org",
    "@type": "TechArticle",
    "name": "Git Disaster Recovery : Annuler les Erreurs et Corriger l'Historique",
    "description": "Le kit d'urgence pour developpeurs. Apprenez a annuler des commits, resoudre des conflits de merge, recuperer des branches supprimees et maitriser git rebase vs merge.",
    "proficiencyLevel": "Intermediate",
    "inLanguage": "fr"
  }
---

## Annuler des Modifications

Les trois piliers du "j'ai tout casse" : reset, revert et restore. Chacun a une portee et un niveau de danger different.

### git restore — Annuler les Modifications Non Indexees

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

### git reset — Deplacer HEAD en Arriere

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

> **--soft** conserve tout dans l'index. **--mixed** desindexe mais garde les fichiers. **--hard** detruit tout. En cas de doute, utilisez `--soft`.

### git revert — Annuler un Commit en Toute Securite (Historique Public)

```bash
# Create a new commit that undoes a specific commit
git revert abc1234

# Revert without auto-committing (stage changes only)
git revert --no-commit abc1234

# Revert a merge commit (keep parent #1)
git revert -m 1 <merge-commit-hash>
```

> Utilisez `revert` au lieu de `reset` sur les branches partagees — cela ne reecrit pas l'historique.

---

## Reecrire l'Historique

Pour quand vos messages de commit sont embarrassants ou que l'historique de votre branche est un chaos.

### git commit --amend

```bash
# Change the last commit message
git commit --amend -m "better message"

# Add forgotten files to the last commit
git add forgotten-file.txt
git commit --amend --no-edit
```

### git rebase -i (Rebase Interactif)

```bash
# Rewrite the last 3 commits
git rebase -i HEAD~3
```

Dans l'editeur, vous pouvez :

| Commande | Effet                                  |
|----------|----------------------------------------|
| `pick`   | Garder le commit tel quel              |
| `reword` | Changer le message du commit           |
| `edit`   | S'arreter pour modifier le commit      |
| `squash` | Fusionner avec le commit precedent     |
| `fixup`  | Comme squash, mais ignorer le message  |
| `drop`   | Supprimer le commit entierement        |

```bash
# Rebase current branch onto main (linear history)
git rebase main

# Continue after resolving conflicts
git rebase --continue

# Abort a rebase gone wrong
git rebase --abort
```

> **Rebase vs Merge :** Rebase cree un historique lineaire (logs plus propres). Merge preserve la topologie des branches (plus sur pour les branches partagees). Ne jamais rebaser des commits que d'autres ont deja recuperes.

---

## Recuperation

Quand tout est en feu, ces commandes sont votre extincteur.

### git reflog — La Bouee de Sauvetage

Le reflog enregistre chaque mouvement de HEAD. Meme apres un hard reset, vos commits sont toujours la.

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

### git fsck — Trouver les Objets Orphelins

```bash
# Find unreachable commits and blobs
git fsck --unreachable

# Find lost commits specifically
git fsck --lost-found
# Results saved to .git/lost-found/
```

### Recuperer une Branche Supprimee

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

## Scenarios de Catastrophe Courants

### "J'ai commite sur la mauvaise branche"

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

### "Je dois arreter de suivre un fichier mais le garder localement"

```bash
# Remove from git tracking but keep the file on disk
git rm --cached secret-config.env

# Add to .gitignore to prevent future tracking
echo "secret-config.env" >> .gitignore
git add .gitignore
git commit -m "stop tracking secret-config.env"
```

### "Je dois annuler un push"

```bash
# Safe way: revert the commit (creates new commit)
git revert abc1234
git push

# Nuclear option: force push (DANGEROUS on shared branches)
git reset --hard HEAD~1
git push --force-with-lease
```

### "Mon merge a des conflits partout"

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

### git cherry-pick — Recuperer des Commits Specifiques

```bash
# Apply a single commit from another branch
git cherry-pick abc1234

# Apply multiple commits
git cherry-pick abc1234 def5678

# Cherry-pick without committing (stage only)
git cherry-pick --no-commit abc1234
```

---

## Tableau de Reference Rapide

| Situation | Commande |
|-----------|----------|
| Annuler le dernier commit (garder les modifications) | `git reset --soft HEAD~1` |
| Annuler le dernier commit (supprimer les modifications) | `git reset --hard HEAD~1` |
| Annuler un commit pousse | `git revert <hash>` |
| Annuler les modifications d'un fichier | `git restore <file>` |
| Desindexer un fichier | `git restore --staged <file>` |
| Recuperer une branche supprimee | `git reflog` + `git branch name <hash>` |
| Corriger le dernier message de commit | `git commit --amend -m "new msg"` |
| Fusionner les N derniers commits | `git rebase -i HEAD~N` |
| Deplacer un commit vers la bonne branche | `git reset --soft HEAD~1` + stash + switch |
| Arreter de suivre un fichier | `git rm --cached <file>` |
