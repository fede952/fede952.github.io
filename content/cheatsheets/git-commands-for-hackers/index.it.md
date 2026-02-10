---
title: "Protocollo Git: La Guida di Riferimento Essenziale ai Comandi"
description: "Un cheatsheet tattico di Git che copre correzioni di emergenza, firma GPG, operazioni sui branch e flussi di lavoro avanzati. I comandi che ogni sviluppatore e hacker deve conoscere a memoria."
date: 2026-02-10
tags: ["git", "cheatsheet", "version-control", "developer-tools"]
keywords: ["comandi git cheatsheet", "git annullare commit", "git firma gpg", "comandi git branch", "guida git reset", "tutorial git rebase", "comandi git avanzati", "git per hacker"]
draft: false
schema_json: >
  {
    "@context": "https://schema.org",
    "@type": "TechArticle",
    "name": "Protocollo Git: La Guida di Riferimento Essenziale ai Comandi",
    "description": "Cheatsheet completo dei comandi Git che copre correzioni di emergenza, firma GPG, operazioni sui branch e flussi di lavoro avanzati.",
    "proficiencyLevel": "Intermediate",
    "inLanguage": "it"
  }
---

## $ System_Init

Ogni operazione lascia una traccia. Ogni commit è un checkpoint. Git non è solo controllo di versione — è la spina dorsale forense di ogni progetto software. Questo manuale operativo contiene i comandi che userai quotidianamente e quelli che ti salveranno quando tutto si rompe.

I comandi sono organizzati per tipo di missione. Esegui con precisione.

---

## $ Emergency_Fixes

Quando un deploy va storto e la timeline deve essere riscritta.

### Annullare l'ultimo commit (mantenere le modifiche in staging)

```bash
# Annulla l'ultimo commit ma mantiene le tue modifiche nell'area di staging
git reset --soft HEAD~1
```

### Annullare l'ultimo commit (rimuovere dallo staging)

```bash
# Annulla l'ultimo commit e sposta le modifiche nella working directory
git reset --mixed HEAD~1
```

### Reset nucleare (distruggere tutte le modifiche locali)

```bash
# ATTENZIONE: Questo distrugge permanentemente tutto il lavoro non committato
git reset --hard HEAD~1
```

### Modificare il messaggio dell'ultimo commit

```bash
# Correggi un errore nel tuo ultimo messaggio di commit senza creare un nuovo commit
git commit --amend -m "messaggio di commit corretto"
```

### Recuperare un branch eliminato

```bash
# Trova l'hash del commit perso nel reflog
git reflog

# Ricrea il branch dall'hash recuperato
git checkout -b recovered-branch abc1234
```

### Revertare un commit senza riscrivere la cronologia

```bash
# Crea un nuovo commit che annulla un commit specifico (sicuro per branch condivisi)
git revert <commit-hash>
```

---

## $ Stealth_Mode

Firma crittografica e verifica dell'identità. Dimostra che i tuoi commit sono autentici.

### Configurare la firma GPG

```bash
# Elenca le tue chiavi GPG disponibili
gpg --list-secret-keys --keyid-format=long

# Dì a Git quale chiave usare
git config --global user.signingkey YOUR_KEY_ID

# Abilita la firma automatica per tutti i commit
git config --global commit.gpgsign true
```

### Firmare un singolo commit

```bash
# Firma manualmente un commit specifico
git commit -S -m "signed: verified deployment"
```

### Verificare le firme dei commit

```bash
# Controlla la firma sull'ultimo commit
git log --show-signature -1

# Verifica le firme nell'intero log
git log --pretty="format:%h %G? %aN %s"
```

### Firmare i tag per i release

```bash
# Crea un tag di release firmato
git tag -s v1.0.0 -m "Release v1.0.0 - signed"

# Verifica un tag firmato
git tag -v v1.0.0
```

---

## $ Branch_Operations

Gestione tattica dei branch per lo sviluppo parallelo.

### Creare e passare a un nuovo branch

```bash
# Crea un branch feature e passa ad esso in un solo comando
git checkout -b feature/new-module
```

### Elencare tutti i branch (locali e remoti)

```bash
# Mostra tutti i branch inclusi quelli di tracking remoto
git branch -a
```

### Eliminare un branch in sicurezza

```bash
# Elimina un branch locale (solo se completamente merged)
git branch -d feature/old-module

# Forza l'eliminazione di un branch locale (anche se non merged)
git branch -D feature/abandoned-experiment
```

### Eliminare un branch remoto

```bash
# Rimuovi un branch dal repository remoto
git push origin --delete feature/old-module
```

### Rebase su main (cronologia lineare)

```bash
# Riapplica i commit del tuo branch sopra l'ultimo main
git checkout feature/my-work
git rebase main
```

### Rebase interattivo (squash, riordina, modifica)

```bash
# Riscrivi gli ultimi 3 commit in modo interattivo
git rebase -i HEAD~3
```

---

## $ Reconnaissance

Ispeziona lo stato del repository prima di prendere decisioni.

### Visualizzare log compatto con grafico

```bash
# Log su una riga con visualizzazione grafica dei branch
git log --oneline --graph --all --decorate
```

### Mostrare le modifiche nell'area di staging

```bash
# Confronta le modifiche in staging con l'ultimo commit
git diff --cached
```

### Blame su un file (trovare chi ha modificato ogni riga)

```bash
# Mostra autore e commit per ogni riga in un file
git blame path/to/file.py
```

### Cercare nei messaggi di commit

```bash
# Trova commit contenenti una parola chiave specifica nel messaggio
git log --grep="bugfix" --oneline
```

### Trovare quale commit ha introdotto un bug

```bash
# Ricerca binaria attraverso i commit per trovare la modifica che ha rotto il codice
git bisect start
git bisect bad          # Il commit corrente è rotto
git bisect good abc1234 # Questo vecchio commit funzionava
# Git farà il checkout dei commit per farti testare
```

---

## $ Stash_Operations

Metti temporaneamente da parte il lavoro senza committare.

### Stash delle modifiche correnti

```bash
# Salva le modifiche non committate in uno stack temporaneo
git stash push -m "work in progress: auth module"
```

### Elencare tutti gli stash

```bash
# Visualizza tutte le voci in stash
git stash list
```

### Applicare e rimuovere uno stash

```bash
# Ripristina lo stash più recente e rimuovilo dallo stack
git stash pop

# Ripristina uno stash specifico per indice
git stash apply stash@{2}
```

### Creare un branch da uno stash

```bash
# Trasforma uno stash in un branch feature vero e proprio
git stash branch feature/from-stash stash@{0}
```

---

## $ Advanced_Protocols

Comandi potenti per scenari complessi.

### Cherry-pick di un commit da un altro branch

```bash
# Applica un commit specifico da un branch al tuo branch corrente
git cherry-pick <commit-hash>
```

### Pulire i file non tracciati

```bash
# Anteprima di cosa verrà eliminato
git clean -n

# Elimina file e directory non tracciati
git clean -fd
```

### Creare un file patch

```bash
# Esporta l'ultimo commit come file patch portabile
git format-patch -1 HEAD

# Applica un file patch
git am < patch-file.patch
```

### Clone superficiale (risparmiare banda)

```bash
# Clona solo l'ultimo commit (senza la cronologia completa)
git clone --depth 1 https://github.com/user/repo.git
```
