---
title: "Protocolo Git: A Referência Essencial de Comandos"
description: "Um guia tático de Git cobrindo correções de emergência, assinatura GPG, operações de branches e workflows avançados. Os comandos que todo desenvolvedor e hacker precisa memorizar."
date: 2026-02-10
tags: ["git", "cheatsheet", "version-control", "developer-tools"]
keywords: ["comandos git cheatsheet", "git desfazer commit", "git assinatura gpg", "comandos git branch", "guia git reset", "tutorial git rebase", "comandos git avançados", "git para hackers"]
draft: false
schema_json: >
  {
    "@context": "https://schema.org",
    "@type": "TechArticle",
    "name": "Protocolo Git: A Referência Essencial de Comandos",
    "description": "Guia completo de comandos Git cobrindo correções de emergência, assinatura GPG, operações de branches e workflows avançados.",
    "proficiencyLevel": "Intermediate",
    "inLanguage": "pt"
  }
---

## $ System_Init

Toda operação deixa um rastro. Todo commit é um checkpoint. Git não é apenas controle de versão — é a espinha dorsal forense de cada projeto de software. Este manual de campo contém os comandos que você usará diariamente e aqueles que o salvarão quando tudo quebrar.

Os comandos são organizados por tipo de missão. Execute com precisão.

---

## $ Emergency_Fixes

Quando um deploy dá errado e a linha do tempo precisa ser reescrita.

### Desfazer o último commit (manter mudanças em staging)

```bash
# Desfaz o último commit mas mantém suas mudanças na área de staging
git reset --soft HEAD~1
```

### Desfazer o último commit (remover do staging)

```bash
# Desfaz o último commit e move as mudanças de volta para o diretório de trabalho
git reset --mixed HEAD~1
```

### Reset nuclear (destruir todas as mudanças locais)

```bash
# AVISO: Isto destrói permanentemente todo o trabalho não commitado
git reset --hard HEAD~1
```

### Alterar a mensagem do último commit

```bash
# Corrige um erro de digitação na sua última mensagem de commit sem criar um novo commit
git commit --amend -m "mensagem de commit corrigida"
```

### Recuperar um branch deletado

```bash
# Encontre o hash do commit perdido no reflog
git reflog

# Recrie o branch a partir do hash recuperado
git checkout -b recovered-branch abc1234
```

### Reverter um commit sem reescrever o histórico

```bash
# Cria um novo commit que desfaz um commit específico (seguro para branches compartilhados)
git revert <commit-hash>
```

---

## $ Stealth_Mode

Assinatura criptográfica e verificação de identidade. Prove que seus commits são autênticos.

### Configurar assinatura GPG

```bash
# Liste suas chaves GPG disponíveis
gpg --list-secret-keys --keyid-format=long

# Diga ao Git qual chave usar
git config --global user.signingkey YOUR_KEY_ID

# Habilite a assinatura automática para todos os commits
git config --global commit.gpgsign true
```

### Assinar um único commit

```bash
# Assine manualmente um commit específico
git commit -S -m "signed: verified deployment"
```

### Verificar assinaturas de commits

```bash
# Verifique a assinatura no último commit
git log --show-signature -1

# Verifique assinaturas em todo o log
git log --pretty="format:%h %G? %aN %s"
```

### Assinar tags para releases

```bash
# Crie uma tag de release assinada
git tag -s v1.0.0 -m "Release v1.0.0 - signed"

# Verifique uma tag assinada
git tag -v v1.0.0
```

---

## $ Branch_Operations

Gerenciamento tático de branches para desenvolvimento paralelo.

### Criar e mudar para um novo branch

```bash
# Crie um branch de feature e mude para ele em um único comando
git checkout -b feature/new-module
```

### Listar todos os branches (locais e remotos)

```bash
# Mostre todos os branches incluindo branches de rastreamento remoto
git branch -a
```

### Deletar um branch com segurança

```bash
# Delete um branch local (apenas se totalmente mesclado)
git branch -d feature/old-module

# Force a deleção de um branch local (mesmo se não mesclado)
git branch -D feature/abandoned-experiment
```

### Deletar um branch remoto

```bash
# Remova um branch do repositório remoto
git push origin --delete feature/old-module
```

### Rebase em main (histórico linear)

```bash
# Reaplique os commits do seu branch sobre o último main
git checkout feature/my-work
git rebase main
```

### Rebase interativo (squash, reordenar, editar)

```bash
# Reescreva os últimos 3 commits de forma interativa
git rebase -i HEAD~3
```

---

## $ Reconnaissance

Inspecione o estado do repositório antes de tomar decisões.

### Ver log compacto com gráfico

```bash
# Log de uma linha com visualização gráfica de branches
git log --oneline --graph --all --decorate
```

### Mostrar mudanças na área de staging

```bash
# Compare mudanças em staging com o último commit
git diff --cached
```

### Blame em um arquivo (encontrar quem mudou cada linha)

```bash
# Mostre autor e commit para cada linha em um arquivo
git blame path/to/file.py
```

### Buscar em mensagens de commit

```bash
# Encontre commits contendo uma palavra-chave específica na mensagem
git log --grep="bugfix" --oneline
```

### Encontrar qual commit introduziu um bug

```bash
# Busca binária através de commits para encontrar a mudança que quebrou o código
git bisect start
git bisect bad          # O commit atual está quebrado
git bisect good abc1234 # Este commit antigo estava funcionando
# Git fará checkout de commits para você testar
```

---

## $ Stash_Operations

Guarde temporariamente o trabalho sem fazer commit.

### Fazer stash das mudanças atuais

```bash
# Salve mudanças não commitadas em uma pilha temporária
git stash push -m "work in progress: auth module"
```

### Listar todos os stashes

```bash
# Veja todas as entradas em stash
git stash list
```

### Aplicar e remover um stash

```bash
# Restaure o stash mais recente e remova-o da pilha
git stash pop

# Restaure um stash específico por índice
git stash apply stash@{2}
```

### Criar um branch a partir de um stash

```bash
# Transforme um stash em um branch de feature apropriado
git stash branch feature/from-stash stash@{0}
```

---

## $ Advanced_Protocols

Comandos poderosos para cenários complexos.

### Cherry-pick de um commit de outro branch

```bash
# Aplique um commit específico de um branch ao seu branch atual
git cherry-pick <commit-hash>
```

### Limpar arquivos não rastreados

```bash
# Visualize o que será deletado
git clean -n

# Delete arquivos e diretórios não rastreados
git clean -fd
```

### Criar um arquivo patch

```bash
# Exporte o último commit como um arquivo patch portátil
git format-patch -1 HEAD

# Aplique um arquivo patch
git am < patch-file.patch
```

### Clone superficial (economizar largura de banda)

```bash
# Clone apenas o último commit (sem histórico completo)
git clone --depth 1 https://github.com/user/repo.git
```
