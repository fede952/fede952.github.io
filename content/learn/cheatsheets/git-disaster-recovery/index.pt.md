---
title: "Git Disaster Recovery: Desfazendo Erros e Corrigindo o Histórico"
description: "O kit de emergência para desenvolvedores. Aprenda a desfazer commits, resolver conflitos de merge, recuperar branches deletadas e dominar git rebase vs merge."
date: 2026-02-13
tags: ["git", "cheatsheet", "devops", "version-control"]
keywords: ["git desfazer commit", "git reset hard vs soft", "recuperar branch deletada", "git rebase tutorial", "resolver conflito merge", "git cherry-pick"]
draft: false
proficiency: "Intermediate"
aliases: ["/cheatsheets/git-disaster-recovery/"]
---

## Desfazendo alterações

Os três pilares do "eu errei": reset, revert e restore. Cada um tem um escopo e nível de perigo diferente.

### git restore — Descartar Alterações Não Preparadas

```bash
# Descartar alterações em um único arquivo (apenas diretório de trabalho)
git restore file.txt

# Descartar TODAS as alterações não preparadas
git restore .

# Remover arquivo da área de staging (manter alterações no diretório de trabalho)
git restore --staged file.txt

# Restaurar um arquivo para a versão de um commit específico
git restore --source=abc1234 file.txt
```

### git reset — Mover o HEAD Para Trás

```bash
# Soft reset: desfaz o commit, mantém alterações na área de staging
git reset --soft HEAD~1

# Mixed reset (padrão): desfaz o commit, remove do staging, mantém arquivos
git reset HEAD~1

# Hard reset: desfaz o commit, APAGA todas as alterações permanentemente
git reset --hard HEAD~1

# Reset para um commit específico
git reset --hard abc1234
```

> **--soft** mantém tudo na área de staging. **--mixed** remove do staging mas mantém os arquivos. **--hard** destrói tudo. Na dúvida, use `--soft`.

### git revert — Desfazer um Commit com Segurança (Histórico Público)

```bash
# Criar um novo commit que desfaz um commit específico
git revert abc1234

# Reverter sem fazer commit automaticamente (apenas preparar alterações)
git revert --no-commit abc1234

# Reverter um commit de merge (manter parent #1)
git revert -m 1 <merge-commit-hash>
```

> Use `revert` em vez de `reset` em branches compartilhadas — ele não reescreve o histórico.

---

## Reescrevendo o histórico

Para quando suas mensagens de commit são vergonhosas ou o histórico da branch está uma bagunça.

### git commit --amend

```bash
# Alterar a mensagem do último commit
git commit --amend -m "better message"

# Adicionar arquivos esquecidos ao último commit
git add forgotten-file.txt
git commit --amend --no-edit
```

### git rebase -i (Rebase Interativo)

```bash
# Reescrever os últimos 3 commits
git rebase -i HEAD~3
```

No editor, você pode:

| Comando  | Efeito                                |
|----------|---------------------------------------|
| `pick`   | Manter o commit como está             |
| `reword` | Alterar a mensagem do commit          |
| `edit`   | Parar para alterar o commit           |
| `squash` | Unir ao commit anterior               |
| `fixup`  | Como squash, mas descarta a mensagem  |
| `drop`   | Deletar o commit completamente        |

```bash
# Rebase da branch atual sobre a main (histórico linear)
git rebase main

# Continuar após resolver conflitos
git rebase --continue

# Abortar um rebase que deu errado
git rebase --abort
```

> **Rebase vs Merge:** Rebase cria um histórico linear (logs mais limpos). Merge preserva a topologia das branches (mais seguro para branches compartilhadas). Nunca faça rebase de commits que outros já baixaram.

---

## Recuperar commits e branches perdidos

Quando tudo está pegando fogo, esses comandos são seu extintor de incêndio.

### git reflog — O Salva-Vidas

O reflog registra cada movimento do HEAD. Mesmo após um hard reset, seus commits ainda estão lá.

```bash
# Ver o reflog (todas as posições recentes do HEAD)
git reflog

# Exemplo de saída:
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
# Encontrar commits e blobs inalcançáveis
git fsck --unreachable

# Encontrar commits perdidos especificamente
git fsck --lost-found
# Resultados salvos em .git/lost-found/
```

### Recuperar uma Branch Deletada

```bash
# Passo 1: encontrar o último commit da branch deletada
git reflog | grep "branch-name"
# Ou buscar pela mensagem do commit
git reflog | grep "feature I was working on"

# Passo 2: recriar a branch naquele commit
git branch recovered-branch abc1234

# Alternativa: encontrar e restaurar de uma vez
git checkout -b recovered-branch HEAD@{5}
```

---

## Cenários comuns de desastre

### "Fiz commit na branch errada"

```bash
# Passo 1: Anotar o hash do commit
git log --oneline -1
# abc1234 accidental commit

# Passo 2: Desfazer o commit na branch errada (manter alterações)
git reset --soft HEAD~1

# Passo 3: Guardar, trocar de branch e aplicar
git stash
git checkout correct-branch
git stash pop
git add . && git commit -m "feature in the right place"
```

### "Preciso parar de rastrear um arquivo mas mantê-lo localmente"

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

# Opção nuclear: force push (PERIGOSO em branches compartilhadas)
git reset --hard HEAD~1
git push --force-with-lease
```

### "Meu merge tem conflitos por todo lado"

```bash
# Ver quais arquivos têm conflitos
git status

# Para cada arquivo com conflito, procure os marcadores de conflito:
# <<<<<<< HEAD
# suas alterações
# =======
# alterações deles
# >>>>>>> branch-name

# Após resolver todos os conflitos:
git add .
git commit

# Ou abortar o merge completamente
git merge --abort
```

### git cherry-pick — Pegar Commits Específicos

```bash
# Aplicar um único commit de outra branch
git cherry-pick abc1234

# Aplicar múltiplos commits
git cherry-pick abc1234 def5678

# Cherry-pick sem fazer commit (apenas preparar)
git cherry-pick --no-commit abc1234
```

---

## Tabela de referência rápida

| Situação | Comando |
|----------|---------|
| Desfazer último commit (manter alterações) | `git reset --soft HEAD~1` |
| Desfazer último commit (apagar alterações) | `git reset --hard HEAD~1` |
| Desfazer um commit já enviado | `git revert <hash>` |
| Descartar alterações de arquivo | `git restore <file>` |
| Remover arquivo do staging | `git restore --staged <file>` |
| Recuperar branch deletada | `git reflog` + `git branch name <hash>` |
| Corrigir mensagem do último commit | `git commit --amend -m "new msg"` |
| Unir últimos N commits | `git rebase -i HEAD~N` |
| Mover commit para branch correta | `git reset --soft HEAD~1` + stash + switch |
| Parar de rastrear um arquivo | `git rm --cached <file>` |
