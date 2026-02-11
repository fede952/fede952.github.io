---
title: "CORREÇÃO: fatal: refusing to merge unrelated histories"
description: "Corrija o erro do Git 'refusing to merge unrelated histories' ao fazer pull ou merge. Entenda por que acontece e como combinar com segurança dois repositórios independentes."
date: 2026-02-11
tags: ["git", "debug", "devops", "version-control"]
keywords: ["refusing to merge unrelated histories", "git pull unrelated histories", "git merge unrelated histories", "allow unrelated histories", "fatal refusing to merge", "git pull origin main error", "git merge two repos", "git init push error", "github first commit merge", "git unrelated histories fix"]
draft: false
schema_json: >
  {
    "@context": "https://schema.org",
    "@type": "TechArticle",
    "name": "CORREÇÃO: fatal: refusing to merge unrelated histories",
    "description": "Como corrigir o erro do Git refusing to merge unrelated histories ao combinar repositórios independentes.",
    "proficiencyLevel": "Beginner",
    "inLanguage": "pt"
  }
---

## O Erro

Você tenta fazer pull de um repositório remoto ou merge de uma branch e o Git recusa:

```
fatal: refusing to merge unrelated histories
```

Isso geralmente acontece quando você executa:

```bash
git pull origin main
```

E os repositórios local e remoto não têm um commit ancestral em comum — o Git os vê como dois projetos completamente separados e se recusa a combiná-los automaticamente.

---

## A Correção Rápida

Adicione a flag `--allow-unrelated-histories` para forçar o Git a fazer merge das duas histórias independentes:

```bash
# Pull and merge unrelated histories
git pull origin main --allow-unrelated-histories
```

Ou se você está fazendo merge de uma branch:

```bash
# Merge a branch with unrelated history
git merge other-branch --allow-unrelated-histories
```

O Git tentará o merge. Se houver conflitos de arquivos, resolva-os normalmente:

```bash
# Check which files conflict
git status

# After resolving conflicts in your editor
git add .
git commit -m "Merge unrelated histories"
```

---

## Por Que Isso Acontece

Este erro ocorre quando dois repositórios Git não compartilham nenhum histórico de commits em comum. Os cenários mais comuns:

### Cenário 1: Novo repo com conflito de README

Você criou um repositório local com `git init` e fez alguns commits. Depois criou um repo no GitHub **com um README.md** (ou `.gitignore` ou `LICENSE`). Agora quando você tenta fazer pull, o remoto tem um commit raiz que seu repo local desconhece.

```bash
# This is the classic cause:
mkdir my-project && cd my-project
git init
echo "hello" > app.py
git add . && git commit -m "first commit"
git remote add origin https://github.com/user/my-project.git
git pull origin main   # ERROR: unrelated histories
```

**Prevenção:** Ao criar um novo repo no GitHub para fazer push de um projeto local existente, crie o repo remoto **sem** inicializá-lo (sem README, sem .gitignore, sem licença). Depois faça push diretamente.

### Cenário 2: Unir dois repositórios independentes

Você quer combinar dois projetos separados em um único repositório. Como foram criados independentemente, eles têm árvores de commits completamente diferentes.

### Cenário 3: Histórico reescrito

Alguém executou `git rebase` ou `git filter-branch` no remoto, o que reescreveu os commits raiz. O histórico do remoto não compartilha mais um ancestral com sua cópia local.

---

## É Seguro?

Sim — `--allow-unrelated-histories` simplesmente diz ao Git para prosseguir com o merge mesmo que as duas branches não tenham uma base comum. Não deleta, sobrescreve ou faz rebase de nada. Se houver arquivos conflitantes, o Git os marcará como conflitos e permitirá que você os resolva manualmente, exatamente como um merge normal.

A flag foi adicionada no **Git 2.9** (junho de 2016). Antes dessa versão, o Git permitia merges não relacionados por padrão.

---

## Recursos Relacionados

Domine merges avançados, rebases e resolução de conflitos com nosso [Git Protocol Cheatsheet](/cheatsheets/git-commands-for-hackers/) — cada comando Git que um desenvolvedor precisa, organizado por workflow.
