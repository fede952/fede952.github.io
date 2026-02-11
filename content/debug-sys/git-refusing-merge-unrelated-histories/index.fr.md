---
title: "CORRECTIF: fatal: refusing to merge unrelated histories"
description: "Corrigez l'erreur Git 'refusing to merge unrelated histories' lors d'un pull ou d'un merge. Comprenez pourquoi elle survient et comment combiner en toute sécurité deux dépôts indépendants."
date: 2026-02-11
tags: ["git", "debug", "devops", "version-control"]
keywords: ["refusing to merge unrelated histories", "git pull unrelated histories", "git merge unrelated histories", "allow unrelated histories", "fatal refusing to merge", "git pull origin main error", "git merge two repos", "git init push error", "github first commit merge", "git unrelated histories fix"]
draft: false
schema_json: >
  {
    "@context": "https://schema.org",
    "@type": "TechArticle",
    "name": "CORRECTIF: fatal: refusing to merge unrelated histories",
    "description": "Comment corriger l'erreur Git refusing to merge unrelated histories lors de la combinaison de dépôts indépendants.",
    "proficiencyLevel": "Beginner",
    "inLanguage": "fr"
  }
---

## L'Erreur

Vous essayez de faire un pull depuis un dépôt distant ou de fusionner une branche et Git refuse :

```
fatal: refusing to merge unrelated histories
```

Cela se produit généralement lorsque vous exécutez :

```bash
git pull origin main
```

Et les dépôts local et distant n'ont aucun commit ancêtre en commun — Git les considère comme deux projets complètement séparés et refuse de les combiner automatiquement.

---

## La Solution Rapide

Ajoutez le flag `--allow-unrelated-histories` pour forcer Git à fusionner les deux historiques indépendants :

```bash
# Pull and merge unrelated histories
git pull origin main --allow-unrelated-histories
```

Ou si vous fusionnez une branche :

```bash
# Merge a branch with unrelated history
git merge other-branch --allow-unrelated-histories
```

Git tentera la fusion. S'il y a des conflits de fichiers, résolvez-les normalement :

```bash
# Check which files conflict
git status

# After resolving conflicts in your editor
git add .
git commit -m "Merge unrelated histories"
```

---

## Pourquoi Cela Se Produit

Cette erreur survient lorsque deux dépôts Git ne partagent aucun historique de commits en commun. Les scénarios les plus courants :

### Scénario 1 : Nouveau repo avec conflit de README

Vous avez créé un dépôt local avec `git init` et effectué quelques commits. Puis vous avez créé un repo GitHub **avec un README.md** (ou `.gitignore` ou `LICENSE`). Maintenant, lorsque vous essayez de faire un pull, le distant a un commit racine que votre repo local ne connaît pas.

```bash
# This is the classic cause:
mkdir my-project && cd my-project
git init
echo "hello" > app.py
git add . && git commit -m "first commit"
git remote add origin https://github.com/user/my-project.git
git pull origin main   # ERROR: unrelated histories
```

**Prévention :** Lorsque vous créez un nouveau repo GitHub pour pousser un projet local existant, créez le repo distant **sans** l'initialiser (pas de README, pas de .gitignore, pas de licence). Puis faites un push directement.

### Scénario 2 : Fusionner deux dépôts indépendants

Vous souhaitez combiner deux projets séparés en un seul dépôt. Comme ils ont été créés indépendamment, ils ont des arbres de commits complètement différents.

### Scénario 3 : Historique réécrit

Quelqu'un a exécuté `git rebase` ou `git filter-branch` sur le distant, ce qui a réécrit les commits racine. L'historique du distant ne partage plus d'ancêtre avec votre copie locale.

---

## Est-ce Sûr ?

Oui — `--allow-unrelated-histories` dit simplement à Git de procéder à la fusion même si les deux branches n'ont pas de base commune. Cela ne supprime, n'écrase ni ne rebase quoi que ce soit. S'il y a des fichiers en conflit, Git les marquera comme conflits et vous laissera les résoudre manuellement, exactement comme une fusion normale.

Le flag a été ajouté dans **Git 2.9** (juin 2016). Avant cette version, Git autorisait les fusions sans relation par défaut.

---

## Ressources Associées

Maîtrisez les merges avancés, les rebases et la résolution de conflits avec notre [Git Protocol Cheatsheet](/cheatsheets/git-commands-for-hackers/) — chaque commande Git dont un développeur a besoin, organisée par workflow.
