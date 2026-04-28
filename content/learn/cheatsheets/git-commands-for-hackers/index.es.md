---
title: "Protocolo Git: La Guía de Referencia Esencial de Comandos"
description: "Una hoja de referencia táctica de Git que cubre correcciones de emergencia, firma GPG, operaciones de ramas y flujos de trabajo avanzados. Los comandos que todo desarrollador y hacker necesita memorizar."
date: 2026-02-10
tags: ["git", "cheatsheet", "version-control", "developer-tools"]
keywords: ["comandos git cheatsheet", "git deshacer commit", "git firma gpg", "comandos git branch", "guía git reset", "tutorial git rebase", "comandos git avanzados", "git para hackers"]
draft: false
schema_json: >
  {
    "@context": "https://schema.org",
    "@type": "TechArticle",
    "name": "Protocolo Git: La Guía de Referencia Esencial de Comandos",
    "description": "Hoja de referencia completa de comandos Git que cubre correcciones de emergencia, firma GPG, operaciones de ramas y flujos de trabajo avanzados.",
    "proficiencyLevel": "Intermediate",
    "inLanguage": "es"
  }
---

## $ System_Init

Cada operación deja un rastro. Cada commit es un punto de control. Git no es solo control de versiones — es la columna vertebral forense de cada proyecto de software. Este manual de campo contiene los comandos que usarás a diario y los que te salvarán cuando todo se rompa.

Los comandos están organizados por tipo de misión. Ejecuta con precisión.

---

## $ Emergency_Fixes

Cuando un despliegue sale mal y la línea de tiempo necesita reescribirse.

### Deshacer el último commit (mantener cambios en staging)

```bash
# Deshace el último commit pero mantiene tus cambios en el área de staging
git reset --soft HEAD~1
```

### Deshacer el último commit (quitar del staging)

```bash
# Deshace el último commit y mueve los cambios de vuelta al directorio de trabajo
git reset --mixed HEAD~1
```

### Reset nuclear (destruir todos los cambios locales)

```bash
# ADVERTENCIA: Esto destruye permanentemente todo el trabajo no commiteado
git reset --hard HEAD~1
```

### Modificar el mensaje del último commit

```bash
# Corrige un error tipográfico en tu último mensaje de commit sin crear un nuevo commit
git commit --amend -m "mensaje de commit corregido"
```

### Recuperar una rama eliminada

```bash
# Encuentra el hash del commit perdido en el reflog
git reflog

# Recrea la rama desde el hash recuperado
git checkout -b recovered-branch abc1234
```

### Revertir un commit sin reescribir el historial

```bash
# Crea un nuevo commit que deshace un commit específico (seguro para ramas compartidas)
git revert <commit-hash>
```

---

## $ Stealth_Mode

Firma criptográfica y verificación de identidad. Demuestra que tus commits son auténticos.

### Configurar firma GPG

```bash
# Lista tus claves GPG disponibles
gpg --list-secret-keys --keyid-format=long

# Indica a Git qué clave usar
git config --global user.signingkey YOUR_KEY_ID

# Habilita la firma automática para todos los commits
git config --global commit.gpgsign true
```

### Firmar un solo commit

```bash
# Firma manualmente un commit específico
git commit -S -m "signed: verified deployment"
```

### Verificar firmas de commits

```bash
# Verifica la firma en el último commit
git log --show-signature -1

# Verifica firmas en todo el log
git log --pretty="format:%h %G? %aN %s"
```

### Firmar tags para releases

```bash
# Crea un tag de release firmado
git tag -s v1.0.0 -m "Release v1.0.0 - signed"

# Verifica un tag firmado
git tag -v v1.0.0
```

---

## $ Branch_Operations

Gestión táctica de ramas para desarrollo paralelo.

### Crear y cambiar a una nueva rama

```bash
# Crea una rama de feature y cambia a ella en un solo comando
git checkout -b feature/new-module
```

### Listar todas las ramas (locales y remotas)

```bash
# Muestra todas las ramas incluyendo las ramas de seguimiento remoto
git branch -a
```

### Eliminar una rama de forma segura

```bash
# Elimina una rama local (solo si está completamente fusionada)
git branch -d feature/old-module

# Fuerza la eliminación de una rama local (incluso si no está fusionada)
git branch -D feature/abandoned-experiment
```

### Eliminar una rama remota

```bash
# Elimina una rama del repositorio remoto
git push origin --delete feature/old-module
```

### Rebase sobre main (historial lineal)

```bash
# Reaplica los commits de tu rama sobre el último main
git checkout feature/my-work
git rebase main
```

### Rebase interactivo (squash, reordenar, editar)

```bash
# Reescribe los últimos 3 commits de forma interactiva
git rebase -i HEAD~3
```

---

## $ Reconnaissance

Inspecciona el estado del repositorio antes de tomar decisiones.

### Ver log compacto con gráfico

```bash
# Log de una línea con visualización gráfica de ramas
git log --oneline --graph --all --decorate
```

### Mostrar cambios en el área de staging

```bash
# Compara los cambios en staging contra el último commit
git diff --cached
```

### Blame en un archivo (encontrar quién cambió cada línea)

```bash
# Muestra autor y commit para cada línea en un archivo
git blame path/to/file.py
```

### Buscar en mensajes de commit

```bash
# Encuentra commits que contengan una palabra clave específica en el mensaje
git log --grep="bugfix" --oneline
```

### Encontrar qué commit introdujo un bug

```bash
# Búsqueda binaria a través de commits para encontrar el cambio que rompió el código
git bisect start
git bisect bad          # El commit actual está roto
git bisect good abc1234 # Este commit antiguo funcionaba
# Git hará checkout de commits para que los pruebes
```

---

## $ Stash_Operations

Guarda temporalmente el trabajo sin hacer commit.

### Hacer stash de los cambios actuales

```bash
# Guarda cambios no commiteados en una pila temporal
git stash push -m "work in progress: auth module"
```

### Listar todos los stashes

```bash
# Ver todas las entradas guardadas en stash
git stash list
```

### Aplicar y eliminar un stash

```bash
# Restaura el stash más reciente y lo elimina de la pila
git stash pop

# Restaura un stash específico por índice
git stash apply stash@{2}
```

### Crear una rama desde un stash

```bash
# Convierte un stash en una rama de feature propiamente dicha
git stash branch feature/from-stash stash@{0}
```

---

## $ Advanced_Protocols

Comandos potentes para escenarios complejos.

### Cherry-pick de un commit desde otra rama

```bash
# Aplica un commit específico de una rama a tu rama actual
git cherry-pick <commit-hash>
```

### Limpiar archivos no rastreados

```bash
# Vista previa de lo que se eliminará
git clean -n

# Elimina archivos y directorios no rastreados
git clean -fd
```

### Crear un archivo patch

```bash
# Exporta el último commit como un archivo patch portátil
git format-patch -1 HEAD

# Aplica un archivo patch
git am < patch-file.patch
```

### Clon superficial (ahorrar ancho de banda)

```bash
# Clona solo el último commit (sin el historial completo)
git clone --depth 1 https://github.com/user/repo.git
```
