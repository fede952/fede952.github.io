---
title: "Protocole Git : Le Guide de Référence Essentiel des Commandes"
description: "Un aide-mémoire tactique Git couvrant les corrections d'urgence, la signature GPG, les opérations de branches et les workflows avancés. Les commandes que chaque développeur et hacker doit mémoriser."
date: 2026-02-10
tags: ["git", "cheatsheet", "version-control", "developer-tools"]
keywords: ["commandes git aide-mémoire", "git annuler commit", "git signature gpg", "commandes git branch", "guide git reset", "tutoriel git rebase", "commandes git avancées", "git pour hackers"]
draft: false
schema_json: >
  {
    "@context": "https://schema.org",
    "@type": "TechArticle",
    "name": "Protocole Git : Le Guide de Référence Essentiel des Commandes",
    "description": "Aide-mémoire complet des commandes Git couvrant les corrections d'urgence, la signature GPG, les opérations de branches et les workflows avancés.",
    "proficiencyLevel": "Intermediate",
    "inLanguage": "fr"
  }
---

## $ System_Init

Chaque opération laisse une trace. Chaque commit est un point de contrôle. Git n'est pas seulement du contrôle de version — c'est l'épine dorsale médico-légale de chaque projet logiciel. Ce manuel de terrain contient les commandes que vous utiliserez quotidiennement et celles qui vous sauveront quand tout s'effondre.

Les commandes sont organisées par type de mission. Exécutez avec précision.

---

## $ Emergency_Fixes

Quand un déploiement tourne mal et que la chronologie doit être réécrite.

### Annuler le dernier commit (garder les modifications en staging)

```bash
# Annule le dernier commit mais garde vos modifications dans la zone de staging
git reset --soft HEAD~1
```

### Annuler le dernier commit (retirer du staging)

```bash
# Annule le dernier commit et déplace les modifications vers le répertoire de travail
git reset --mixed HEAD~1
```

### Réinitialisation nucléaire (détruire tous les changements locaux)

```bash
# ATTENTION : Ceci détruit définitivement tout le travail non committé
git reset --hard HEAD~1
```

### Modifier le message du dernier commit

```bash
# Corrige une faute de frappe dans votre dernier message de commit sans créer un nouveau commit
git commit --amend -m "message de commit corrigé"
```

### Récupérer une branche supprimée

```bash
# Trouve le hash du commit perdu dans le reflog
git reflog

# Recrée la branche à partir du hash récupéré
git checkout -b recovered-branch abc1234
```

### Inverser un commit sans réécrire l'historique

```bash
# Crée un nouveau commit qui annule un commit spécifique (sûr pour les branches partagées)
git revert <commit-hash>
```

---

## $ Stealth_Mode

Signature cryptographique et vérification d'identité. Prouvez que vos commits sont authentiques.

### Configurer la signature GPG

```bash
# Liste vos clés GPG disponibles
gpg --list-secret-keys --keyid-format=long

# Indique à Git quelle clé utiliser
git config --global user.signingkey YOUR_KEY_ID

# Active la signature automatique pour tous les commits
git config --global commit.gpgsign true
```

### Signer un seul commit

```bash
# Signe manuellement un commit spécifique
git commit -S -m "signed: verified deployment"
```

### Vérifier les signatures des commits

```bash
# Vérifie la signature sur le dernier commit
git log --show-signature -1

# Vérifie les signatures dans tout le log
git log --pretty="format:%h %G? %aN %s"
```

### Signer les tags pour les releases

```bash
# Crée un tag de release signé
git tag -s v1.0.0 -m "Release v1.0.0 - signed"

# Vérifie un tag signé
git tag -v v1.0.0
```

---

## $ Branch_Operations

Gestion tactique des branches pour le développement parallèle.

### Créer et basculer vers une nouvelle branche

```bash
# Crée une branche de feature et bascule vers elle en une seule commande
git checkout -b feature/new-module
```

### Lister toutes les branches (locales et distantes)

```bash
# Affiche toutes les branches y compris les branches de suivi distant
git branch -a
```

### Supprimer une branche en toute sécurité

```bash
# Supprime une branche locale (uniquement si entièrement fusionnée)
git branch -d feature/old-module

# Force la suppression d'une branche locale (même si non fusionnée)
git branch -D feature/abandoned-experiment
```

### Supprimer une branche distante

```bash
# Supprime une branche du dépôt distant
git push origin --delete feature/old-module
```

### Rebaser sur main (historique linéaire)

```bash
# Réapplique les commits de votre branche au-dessus du dernier main
git checkout feature/my-work
git rebase main
```

### Rebase interactif (squash, réordonner, éditer)

```bash
# Réécrit les 3 derniers commits de manière interactive
git rebase -i HEAD~3
```

---

## $ Reconnaissance

Inspectez l'état du dépôt avant de prendre des décisions.

### Afficher un log compact avec graphique

```bash
# Log sur une ligne avec visualisation graphique des branches
git log --oneline --graph --all --decorate
```

### Afficher les modifications dans la zone de staging

```bash
# Compare les modifications en staging avec le dernier commit
git diff --cached
```

### Blame sur un fichier (trouver qui a modifié chaque ligne)

```bash
# Affiche l'auteur et le commit pour chaque ligne d'un fichier
git blame path/to/file.py
```

### Rechercher dans les messages de commit

```bash
# Trouve les commits contenant un mot-clé spécifique dans le message
git log --grep="bugfix" --oneline
```

### Trouver quel commit a introduit un bug

```bash
# Recherche binaire à travers les commits pour trouver le changement qui a cassé le code
git bisect start
git bisect bad          # Le commit actuel est cassé
git bisect good abc1234 # Cet ancien commit fonctionnait
# Git va faire le checkout des commits pour que vous puissiez les tester
```

---

## $ Stash_Operations

Mettez temporairement de côté le travail sans committer.

### Stasher les modifications actuelles

```bash
# Sauvegarde les modifications non committées dans une pile temporaire
git stash push -m "work in progress: auth module"
```

### Lister tous les stashes

```bash
# Affiche toutes les entrées en stash
git stash list
```

### Appliquer et supprimer un stash

```bash
# Restaure le stash le plus récent et le supprime de la pile
git stash pop

# Restaure un stash spécifique par index
git stash apply stash@{2}
```

### Créer une branche à partir d'un stash

```bash
# Transforme un stash en une vraie branche de feature
git stash branch feature/from-stash stash@{0}
```

---

## $ Advanced_Protocols

Commandes puissantes pour des scénarios complexes.

### Cherry-pick d'un commit depuis une autre branche

```bash
# Applique un commit spécifique d'une branche à votre branche actuelle
git cherry-pick <commit-hash>
```

### Nettoyer les fichiers non suivis

```bash
# Aperçu de ce qui sera supprimé
git clean -n

# Supprime les fichiers et répertoires non suivis
git clean -fd
```

### Créer un fichier patch

```bash
# Exporte le dernier commit comme fichier patch portable
git format-patch -1 HEAD

# Applique un fichier patch
git am < patch-file.patch
```

### Clone superficiel (économiser la bande passante)

```bash
# Clone uniquement le dernier commit (pas d'historique complet)
git clone --depth 1 https://github.com/user/repo.git
```
