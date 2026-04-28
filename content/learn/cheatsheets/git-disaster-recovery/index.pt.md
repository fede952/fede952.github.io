---
title: "Git Disaster Recovery: Desfazendo Erros e Corrigindo o Historico"
description: "O kit de emergencia para desenvolvedores. Aprenda a desfazer commits, resolver conflitos de merge, recuperar branches deletadas e dominar git rebase vs merge."
date: 2026-02-13
tags: ["git", "cheatsheet", "devops", "version-control"]
keywords: ["git desfazer commit", "git reset hard vs soft", "recuperar branch deletada", "git rebase tutorial", "resolver conflito merge", "git cherry-pick"]
draft: false
schema_json: >
  {
    "@context": "https://schema.org",
    "@type": "TechArticle",
    "name": "Git Disaster Recovery: Desfazendo Erros e Corrigindo o Historico",
    "description": "O kit de emergencia para desenvolvedores. Aprenda a desfazer commits, resolver conflitos de merge, recuperar branches deletadas e dominar git rebase vs merge.",
    "proficiencyLevel": "Intermediate",
    "inLanguage": "pt"
  }
---

## Desfazendo Alteracoes

Os tres pilares do "eu errei": reset, revert e restore. Cada um tem um escopo e nivel de perigo diferente.

### git restore — Descartar Alteracoes Nao Preparadas

```bash
# Descartar alteracoes em um unico arquivo (apenas diretorio de trabalho)
git restore file.txt

# Descartar TODAS as alteracoes nao preparadas
git restore .

# Remover arquivo da area de staging (manter alteracoes no diretorio de trabalho)
git restore --staged file.txt

# Restaurar um arquivo para a versao de um commit especifico
git restore --source=abc1234 file.txt
```

### git reset — Mover o HEAD Para Tras

```bash
# Soft reset: desfaz o commit, mantem alteracoes na area de staging
git reset --soft HEAD~1

# Mixed reset (padrao): desfaz o commit, remove do staging, mantem arquivos
git reset HEAD~1

# Hard reset: desfaz o commit, APAGA todas as alteracoes permanentemente
git reset --hard HEAD~1

# Reset para um commit especifico
git reset --hard abc1234
```

> **--soft** mantem tudo na area de staging. **--mixed** remove do staging mas mantem os arquivos. **--hard** destroi tudo. Na duvida, use `--soft`.

### git revert — Desfazer um Commit com Seguranca (Historico Publico)

```bash
# Criar um novo commit que desfaz um commit especifico
git revert abc1234

# Reverter sem fazer commit automaticamente (apenas preparar alteracoes)
git revert --no-commit abc1234

# Reverter um commit de merge (manter parent #1)
git revert -m 1 <merge-commit-hash>
```

> Use `revert` em vez de `reset` em branches compartilhadas — ele nao reescreve o historico.

---

## Reescrevendo o Historico

Para quando suas mensagens de commit sao vergonhosas ou o historico da branch esta uma bagunca.

### git commit --amend

```bash
# Alterar a mensagem do ultimo commit
git commit --amend -m "better message"

# Adicionar arquivos esquecidos ao ultimo commit
git add forgotten-file.txt
git commit --amend --no-edit
```

### git rebase -i (Rebase Interativo)

```bash
# Reescrever os ultimos 3 commits
git rebase -i HEAD~3
```

No editor, voce pode:

| Comando  | Efeito                                |
|----------|---------------------------------------|
| `pick`   | Manter o commit como esta             |
| `reword` | Alterar a mensagem do commit          |
| `edit`   | Parar para alterar o commit           |
| `squash` | Unir ao commit anterior               |
| `fixup`  | Como squash, mas descarta a mensagem  |
| `drop`   | Deletar o commit completamente        |

```bash
# Rebase da branch atual sobre a main (historico linear)
git rebase main

# Continuar apos resolver conflitos
git rebase --continue

# Abortar um rebase que deu errado
git rebase --abort
```

> **Rebase vs Merge:** Rebase cria um historico linear (logs mais limpos). Merge preserva a topologia das branches (mais seguro para branches compartilhadas). Nunca faca rebase de commits que outros ja baixaram.

---

## Recuperacao

Quando tudo esta pegando fogo, esses comandos sao seu extintor de incendio.

### git reflog — O Salva-Vidas

O reflog registra cada movimento do HEAD. Mesmo apos um hard reset, seus commits ainda estao la.

```bash
# Ver o reflog (todas as posicoes recentes do HEAD)
git reflog

# Exemplo de saida:
# abc1234 HEAD@{0}: reset: moving to HEAD~3
# def5678 HEAD@{1}: commit: add feature X
# 9ab0123 HEAD@{2}: commit: fix login bug

# Recuperar fazendo reset para uma entrada do reflog
git reset --hard HEAD@{1}

# Ou fazer cherry-pick de um commit perdido
git cherry-pick def5678
```

### git fsck — Encontrar Objetos Perdidos

```bash
# Encontrar commits e blobs inalcancaveis
git fsck --unreachable

# Encontrar commits perdidos especificamente
git fsck --lost-found
# Resultados salvos em .git/lost-found/
```

### Recuperar uma Branch Deletada

```bash
# Passo 1: encontrar o ultimo commit da branch deletada
git reflog | grep "branch-name"
# Ou buscar pela mensagem do commit
git reflog | grep "feature I was working on"

# Passo 2: recriar a branch naquele commit
git branch recovered-branch abc1234

# Alternativa: encontrar e restaurar de uma vez
git checkout -b recovered-branch HEAD@{5}
```

---

## Cenarios Comuns de Desastre

### "Fiz commit na branch errada"

```bash
# Passo 1: Anotar o hash do commit
git log --oneline -1
# abc1234 accidental commit

# Passo 2: Desfazer o commit na branch errada (manter alteracoes)
git reset --soft HEAD~1

# Passo 3: Guardar, trocar de branch e aplicar
git stash
git checkout correct-branch
git stash pop
git add . && git commit -m "feature in the right place"
```

### "Preciso parar de rastrear um arquivo mas mante-lo localmente"

```bash
# Remover do rastreamento do git mas manter o arquivo no disco
git rm --cached secret-config.env

# Adicionar ao .gitignore para evitar rastreamento futuro
echo "secret-config.env" >> .gitignore
git add .gitignore
git commit -m "stop tracking secret-config.env"
```

### "Preciso desfazer um push"

```bash
# Forma segura: reverter o commit (cria novo commit)
git revert abc1234
git push

# Opcao nuclear: force push (PERIGOSO em branches compartilhadas)
git reset --hard HEAD~1
git push --force-with-lease
```

### "Meu merge tem conflitos por todo lado"

```bash
# Ver quais arquivos tem conflitos
git status

# Para cada arquivo com conflito, procure os marcadores de conflito:
# <<<<<<< HEAD
# suas alteracoes
# =======
# alteracoes deles
# >>>>>>> branch-name

# Apos resolver todos os conflitos:
git add .
git commit

# Ou abortar o merge completamente
git merge --abort
```

### git cherry-pick — Pegar Commits Especificos

```bash
# Aplicar um unico commit de outra branch
git cherry-pick abc1234

# Aplicar multiplos commits
git cherry-pick abc1234 def5678

# Cherry-pick sem fazer commit (apenas preparar)
git cherry-pick --no-commit abc1234
```

---

## Tabela de Referencia Rapida

| Situacao | Comando |
|----------|---------|
| Desfazer ultimo commit (manter alteracoes) | `git reset --soft HEAD~1` |
| Desfazer ultimo commit (apagar alteracoes) | `git reset --hard HEAD~1` |
| Desfazer um commit ja enviado | `git revert <hash>` |
| Descartar alteracoes de arquivo | `git restore <file>` |
| Remover arquivo do staging | `git restore --staged <file>` |
| Recuperar branch deletada | `git reflog` + `git branch name <hash>` |
| Corrigir mensagem do ultimo commit | `git commit --amend -m "new msg"` |
| Unir ultimos N commits | `git rebase -i HEAD~N` |
| Mover commit para branch correta | `git reset --soft HEAD~1` + stash + switch |
| Parar de rastrear um arquivo | `git rm --cached <file>` |
