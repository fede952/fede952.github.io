---
title: "SOLUCIÓN: fatal: refusing to merge unrelated histories"
description: "Soluciona el error de Git 'refusing to merge unrelated histories' al hacer pull o merge. Entiende por qué ocurre y cómo combinar de forma segura dos repositorios independientes."
date: 2026-02-11
tags: ["git", "debug", "devops", "version-control"]
keywords: ["refusing to merge unrelated histories", "git pull unrelated histories", "git merge unrelated histories", "allow unrelated histories", "fatal refusing to merge", "git pull origin main error", "git merge two repos", "git init push error", "github first commit merge", "git unrelated histories fix"]
draft: false
schema_json: >
  {
    "@context": "https://schema.org",
    "@type": "TechArticle",
    "name": "SOLUCIÓN: fatal: refusing to merge unrelated histories",
    "description": "Cómo solucionar el error de Git refusing to merge unrelated histories al combinar repositorios independientes.",
    "proficiencyLevel": "Beginner",
    "inLanguage": "es"
  }
---

## El Error

Intentas hacer pull desde un repositorio remoto o fusionar una rama y Git se niega:

```
fatal: refusing to merge unrelated histories
```

Esto ocurre típicamente cuando ejecutas:

```bash
git pull origin main
```

Y los repositorios local y remoto no tienen un commit ancestro en común — Git los ve como dos proyectos completamente separados y se niega a combinarlos automáticamente.

---

## La Solución Rápida

Añade el flag `--allow-unrelated-histories` para forzar a Git a fusionar las dos historias independientes:

```bash
# Pull and merge unrelated histories
git pull origin main --allow-unrelated-histories
```

O si estás fusionando una rama:

```bash
# Merge a branch with unrelated history
git merge other-branch --allow-unrelated-histories
```

Git intentará la fusión. Si hay conflictos en los archivos, resuélvelos normalmente:

```bash
# Check which files conflict
git status

# After resolving conflicts in your editor
git add .
git commit -m "Merge unrelated histories"
```

---

## Por Qué Ocurre

Este error se produce cuando dos repositorios Git no comparten ningún historial de commits en común. Los escenarios más comunes:

### Escenario 1: Nuevo repo con conflicto de README

Creaste un repositorio local con `git init` e hiciste algunos commits. Luego creaste un repo en GitHub **con un README.md** (o `.gitignore` o `LICENSE`). Ahora cuando intentas hacer pull, el remoto tiene un commit raíz que tu repo local desconoce.

```bash
# This is the classic cause:
mkdir my-project && cd my-project
git init
echo "hello" > app.py
git add . && git commit -m "first commit"
git remote add origin https://github.com/user/my-project.git
git pull origin main   # ERROR: unrelated histories
```

**Prevención:** Cuando crees un nuevo repo en GitHub para subir un proyecto local existente, crea el repo remoto **sin** inicializarlo (sin README, sin .gitignore, sin licencia). Luego haz push directamente.

### Escenario 2: Fusionar dos repositorios independientes

Quieres combinar dos proyectos separados en un solo repositorio. Como fueron creados de forma independiente, tienen árboles de commits completamente diferentes.

### Escenario 3: Historial reescrito

Alguien ejecutó `git rebase` o `git filter-branch` en el remoto, lo que reescribió los commits raíz. El historial del remoto ya no comparte un ancestro con tu copia local.

---

## ¿Es Seguro?

Sí — `--allow-unrelated-histories` simplemente le dice a Git que proceda con la fusión aunque las dos ramas no tengan una base común. No elimina, sobrescribe ni hace rebase de nada. Si hay archivos en conflicto, Git los marcará como conflictos y te permitirá resolverlos manualmente, exactamente como una fusión normal.

El flag fue añadido en **Git 2.9** (junio de 2016). Antes de esa versión, Git permitía fusiones sin relación por defecto.

---

## Recursos Relacionados

Domina merges avanzados, rebases y resolución de conflictos con nuestro [Git Protocol Cheatsheet](/cheatsheets/git-commands-for-hackers/) — cada comando Git que un desarrollador necesita, organizado por flujo de trabajo.
