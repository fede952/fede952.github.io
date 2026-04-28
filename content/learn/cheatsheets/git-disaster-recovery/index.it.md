---
title: "Git Disaster Recovery: Annullare Errori e Correggere la Cronologia"
description: "Il kit di emergenza per sviluppatori. Impara come annullare commit, risolvere conflitti di merge, recuperare branch eliminati e padroneggiare git rebase vs merge."
date: 2026-02-13
tags: ["git", "cheatsheet", "devops", "version-control"]
keywords: ["git undo commit", "git reset hard vs soft", "recover deleted branch", "git rebase tutorial", "fix merge conflict", "git cherry-pick"]
draft: false
schema_json: >
  {
    "@context": "https://schema.org",
    "@type": "TechArticle",
    "name": "Git Disaster Recovery: Annullare Errori e Correggere la Cronologia",
    "description": "Il kit di emergenza per sviluppatori. Impara come annullare commit, risolvere conflitti di merge, recuperare branch eliminati e padroneggiare git rebase vs merge.",
    "proficiencyLevel": "Intermediate",
    "inLanguage": "it"
  }
---

## Annullare le Modifiche

I tre pilastri del "ho fatto un pasticcio": reset, revert e restore. Ognuno ha un ambito e un livello di rischio diverso.

### git restore — Scartare le Modifiche Non Staged

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

### git reset — Spostare HEAD Indietro

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

> **--soft** mantiene tutto nello stage. **--mixed** rimuove dallo stage ma conserva i file. **--hard** distrugge tutto. Nel dubbio, usa `--soft`.

### git revert — Annullare un Commit in Sicurezza (Cronologia Pubblica)

```bash
# Create a new commit that undoes a specific commit
git revert abc1234

# Revert without auto-committing (stage changes only)
git revert --no-commit abc1234

# Revert a merge commit (keep parent #1)
git revert -m 1 <merge-commit-hash>
```

> Usa `revert` invece di `reset` sui branch condivisi — non riscrive la cronologia.

---

## Riscrivere la Cronologia

Per quando i tuoi messaggi di commit sono imbarazzanti o la cronologia del branch e un disastro.

### git commit --amend

```bash
# Change the last commit message
git commit --amend -m "better message"

# Add forgotten files to the last commit
git add forgotten-file.txt
git commit --amend --no-edit
```

### git rebase -i (Rebase Interattivo)

```bash
# Rewrite the last 3 commits
git rebase -i HEAD~3
```

Nell'editor, puoi:

| Comando  | Effetto                                  |
|----------|------------------------------------------|
| `pick`   | Mantieni il commit cosi com'e            |
| `reword` | Cambia il messaggio del commit           |
| `edit`   | Fermati per modificare il commit         |
| `squash` | Unisci al commit precedente              |
| `fixup`  | Come squash, ma scarta il messaggio      |
| `drop`   | Elimina il commit completamente          |

```bash
# Rebase current branch onto main (linear history)
git rebase main

# Continue after resolving conflicts
git rebase --continue

# Abort a rebase gone wrong
git rebase --abort
```

> **Rebase vs Merge:** Rebase crea una cronologia lineare (log piu puliti). Merge preserva la topologia dei branch (piu sicuro per i branch condivisi). Non fare mai rebase di commit che altri hanno gia scaricato.

---

## Recupero

Quando tutto va in fiamme, questi comandi sono il tuo estintore.

### git reflog — Il Salvavita

Il reflog registra ogni movimento di HEAD. Anche dopo un hard reset, i tuoi commit sono ancora li.

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

### git fsck — Trovare Oggetti Orfani

```bash
# Find unreachable commits and blobs
git fsck --unreachable

# Find lost commits specifically
git fsck --lost-found
# Results saved to .git/lost-found/
```

### Recuperare un Branch Eliminato

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

## Scenari di Disastro Comuni

### "Ho fatto commit sul branch sbagliato"

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

### "Devo smettere di tracciare un file ma tenerlo in locale"

```bash
# Remove from git tracking but keep the file on disk
git rm --cached secret-config.env

# Add to .gitignore to prevent future tracking
echo "secret-config.env" >> .gitignore
git add .gitignore
git commit -m "stop tracking secret-config.env"
```

### "Devo annullare un push"

```bash
# Safe way: revert the commit (creates new commit)
git revert abc1234
git push

# Nuclear option: force push (DANGEROUS on shared branches)
git reset --hard HEAD~1
git push --force-with-lease
```

### "Il mio merge ha conflitti ovunque"

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

### git cherry-pick — Prendere Commit Specifici

```bash
# Apply a single commit from another branch
git cherry-pick abc1234

# Apply multiple commits
git cherry-pick abc1234 def5678

# Cherry-pick without committing (stage only)
git cherry-pick --no-commit abc1234
```

---

## Tabella di Riferimento Rapido

| Situazione | Comando |
|-----------|---------|
| Annullare l'ultimo commit (mantenere le modifiche) | `git reset --soft HEAD~1` |
| Annullare l'ultimo commit (eliminare le modifiche) | `git reset --hard HEAD~1` |
| Annullare un commit pushato | `git revert <hash>` |
| Scartare le modifiche di un file | `git restore <file>` |
| Rimuovere un file dallo stage | `git restore --staged <file>` |
| Recuperare un branch eliminato | `git reflog` + `git branch name <hash>` |
| Correggere il messaggio dell'ultimo commit | `git commit --amend -m "new msg"` |
| Comprimere gli ultimi N commit | `git rebase -i HEAD~N` |
| Spostare un commit sul branch corretto | `git reset --soft HEAD~1` + stash + switch |
| Smettere di tracciare un file | `git rm --cached <file>` |
