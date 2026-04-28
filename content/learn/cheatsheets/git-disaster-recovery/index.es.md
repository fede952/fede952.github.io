---
title: "Git Disaster Recovery: Deshacer Errores y Corregir el Historial"
description: "El kit de emergencia para desarrolladores. Aprende a deshacer commits, resolver conflictos de merge, recuperar ramas eliminadas y dominar git rebase vs merge."
date: 2026-02-13
tags: ["git", "cheatsheet", "devops", "version-control"]
keywords: ["git deshacer commit", "git reset hard vs soft", "recuperar rama eliminada", "git rebase tutorial", "resolver conflicto merge", "git cherry-pick"]
draft: false
schema_json: >
  {
    "@context": "https://schema.org",
    "@type": "TechArticle",
    "name": "Git Disaster Recovery: Deshacer Errores y Corregir el Historial",
    "description": "El kit de emergencia para desarrolladores. Aprende a deshacer commits, resolver conflictos de merge, recuperar ramas eliminadas y dominar git rebase vs merge.",
    "proficiencyLevel": "Intermediate",
    "inLanguage": "es"
  }
---

## Deshacer Cambios

Los tres pilares de "la regue": reset, revert y restore. Cada uno tiene un alcance y nivel de peligro diferente.

### git restore — Descartar Cambios No Preparados

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

### git reset — Mover HEAD Hacia Atras

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

> **--soft** mantiene todo preparado (staged). **--mixed** quita del staging pero conserva los archivos. **--hard** destruye todo. En caso de duda, usa `--soft`.

### git revert — Deshacer un Commit de Forma Segura (Historial Publico)

```bash
# Create a new commit that undoes a specific commit
git revert abc1234

# Revert without auto-committing (stage changes only)
git revert --no-commit abc1234

# Revert a merge commit (keep parent #1)
git revert -m 1 <merge-commit-hash>
```

> Usa `revert` en vez de `reset` en ramas compartidas — no reescribe el historial.

---

## Reescribir el Historial

Para cuando tus mensajes de commit son vergonzosos o el historial de tu rama es un desastre.

### git commit --amend

```bash
# Change the last commit message
git commit --amend -m "better message"

# Add forgotten files to the last commit
git add forgotten-file.txt
git commit --amend --no-edit
```

### git rebase -i (Rebase Interactivo)

```bash
# Rewrite the last 3 commits
git rebase -i HEAD~3
```

En el editor, puedes:

| Comando  | Efecto                                |
|----------|---------------------------------------|
| `pick`   | Mantener el commit tal cual           |
| `reword` | Cambiar el mensaje del commit         |
| `edit`   | Detenerse para modificar el commit    |
| `squash` | Fusionar con el commit anterior       |
| `fixup`  | Como squash, pero descarta el mensaje |
| `drop`   | Eliminar el commit por completo       |

```bash
# Rebase current branch onto main (linear history)
git rebase main

# Continue after resolving conflicts
git rebase --continue

# Abort a rebase gone wrong
git rebase --abort
```

> **Rebase vs Merge:** Rebase crea un historial lineal (logs mas limpios). Merge preserva la topologia de ramas (mas seguro para ramas compartidas). Nunca hagas rebase de commits que otros ya hayan descargado.

---

## Recuperacion

Cuando todo esta en llamas, estos comandos son tu extintor.

### git reflog — El Salvavidas

El reflog registra cada movimiento de HEAD. Incluso despues de un hard reset, tus commits siguen ahi.

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

### git fsck — Encontrar Objetos Huerfanos

```bash
# Find unreachable commits and blobs
git fsck --unreachable

# Find lost commits specifically
git fsck --lost-found
# Results saved to .git/lost-found/
```

### Recuperar una Rama Eliminada

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

## Escenarios de Desastre Comunes

### "Hice commit en la rama equivocada"

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

### "Necesito dejar de rastrear un archivo pero conservarlo localmente"

```bash
# Remove from git tracking but keep the file on disk
git rm --cached secret-config.env

# Add to .gitignore to prevent future tracking
echo "secret-config.env" >> .gitignore
git add .gitignore
git commit -m "stop tracking secret-config.env"
```

### "Necesito deshacer un push"

```bash
# Safe way: revert the commit (creates new commit)
git revert abc1234
git push

# Nuclear option: force push (DANGEROUS on shared branches)
git reset --hard HEAD~1
git push --force-with-lease
```

### "Mi merge tiene conflictos por todas partes"

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

### git cherry-pick — Tomar Commits Especificos

```bash
# Apply a single commit from another branch
git cherry-pick abc1234

# Apply multiple commits
git cherry-pick abc1234 def5678

# Cherry-pick without committing (stage only)
git cherry-pick --no-commit abc1234
```

---

## Tabla de Referencia Rapida

| Situacion | Comando |
|-----------|---------|
| Deshacer ultimo commit (conservar cambios) | `git reset --soft HEAD~1` |
| Deshacer ultimo commit (eliminar cambios) | `git reset --hard HEAD~1` |
| Deshacer un commit ya pusheado | `git revert <hash>` |
| Descartar cambios en un archivo | `git restore <file>` |
| Quitar un archivo del staging | `git restore --staged <file>` |
| Recuperar rama eliminada | `git reflog` + `git branch name <hash>` |
| Corregir mensaje del ultimo commit | `git commit --amend -m "new msg"` |
| Aplastar los ultimos N commits | `git rebase -i HEAD~N` |
| Mover commit a la rama correcta | `git reset --soft HEAD~1` + stash + switch |
| Dejar de rastrear un archivo | `git rm --cached <file>` |
