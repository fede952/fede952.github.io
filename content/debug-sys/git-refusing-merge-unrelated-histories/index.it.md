---
title: "SOLUZIONE: fatal: refusing to merge unrelated histories"
description: "Risolvi l'errore Git 'refusing to merge unrelated histories' durante pull o merge. Scopri perché succede e come combinare in sicurezza due repository indipendenti."
date: 2026-02-11
tags: ["git", "debug", "devops", "version-control"]
keywords: ["refusing to merge unrelated histories", "git pull unrelated histories", "git merge unrelated histories", "allow unrelated histories", "fatal refusing to merge", "git pull origin main error", "git merge two repos", "git init push error", "github first commit merge", "git unrelated histories fix"]
draft: false
schema_json: >
  {
    "@context": "https://schema.org",
    "@type": "TechArticle",
    "name": "SOLUZIONE: fatal: refusing to merge unrelated histories",
    "description": "Come risolvere l'errore Git refusing to merge unrelated histories quando si combinano repository indipendenti.",
    "proficiencyLevel": "Beginner",
    "inLanguage": "it"
  }
---

## L'Errore

Provi a fare pull da un repository remoto o a unire un branch e Git rifiuta:

```
fatal: refusing to merge unrelated histories
```

Questo accade tipicamente quando esegui:

```bash
git pull origin main
```

E i repository locale e remoto non hanno un commit antenato in comune — Git li vede come due progetti completamente separati e si rifiuta di combinarli automaticamente.

---

## La Soluzione Rapida

Aggiungi il flag `--allow-unrelated-histories` per forzare Git a unire le due cronologie indipendenti:

```bash
# Pull and merge unrelated histories
git pull origin main --allow-unrelated-histories
```

Oppure se stai unendo un branch:

```bash
# Merge a branch with unrelated history
git merge other-branch --allow-unrelated-histories
```

Git tenterà il merge. Se ci sono conflitti nei file, risolvili normalmente:

```bash
# Check which files conflict
git status

# After resolving conflicts in your editor
git add .
git commit -m "Merge unrelated histories"
```

---

## Perché Succede

Questo errore si verifica quando due repository Git non condividono alcuna cronologia di commit in comune. Gli scenari più comuni:

### Scenario 1: Nuovo repo con conflitto README

Hai creato un repository locale con `git init` e fatto alcuni commit. Poi hai creato un repo su GitHub **con un README.md** (o `.gitignore` o `LICENSE`). Ora quando provi a fare pull, il remoto ha un commit radice che il tuo repo locale non conosce.

```bash
# This is the classic cause:
mkdir my-project && cd my-project
git init
echo "hello" > app.py
git add . && git commit -m "first commit"
git remote add origin https://github.com/user/my-project.git
git pull origin main   # ERROR: unrelated histories
```

**Prevenzione:** Quando crei un nuovo repo su GitHub per pushare un progetto locale esistente, crea il repo remoto **senza** inizializzarlo (niente README, niente .gitignore, niente licenza). Poi fai push direttamente.

### Scenario 2: Unire due repository indipendenti

Vuoi combinare due progetti separati in un unico repository. Poiché sono stati creati indipendentemente, hanno alberi di commit completamente diversi.

### Scenario 3: Cronologia riscritta

Qualcuno ha eseguito `git rebase` o `git filter-branch` sul remoto, riscrivendo i commit radice. La cronologia del remoto non condivide più un antenato con la tua copia locale.

---

## È Sicuro?

Sì — `--allow-unrelated-histories` dice semplicemente a Git di procedere con il merge anche se i due branch non hanno una base comune. Non cancella, sovrascrive o fa rebase di nulla. Se ci sono file in conflitto, Git li segnerà come conflitti e ti permetterà di risolverli manualmente, esattamente come un merge normale.

Il flag è stato aggiunto in **Git 2.9** (giugno 2016). Prima di quella versione, Git permetteva i merge senza relazione per impostazione predefinita.

---

## Risorse Correlate

Padroneggia merge avanzati, rebase e risoluzione dei conflitti con il nostro [Git Protocol Cheatsheet](/cheatsheets/git-commands-for-hackers/) — ogni comando Git di cui uno sviluppatore ha bisogno, organizzato per workflow.
