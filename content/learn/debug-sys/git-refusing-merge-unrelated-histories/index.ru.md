---
title: "ИСПРАВЛЕНИЕ: fatal: refusing to merge unrelated histories"
description: "Исправьте ошибку Git 'refusing to merge unrelated histories' при pull или merge. Узнайте, почему она возникает и как безопасно объединить два независимых репозитория."
date: 2026-02-11
tags: ["git", "debug", "devops", "version-control"]
keywords: ["refusing to merge unrelated histories", "git pull unrelated histories", "git merge unrelated histories", "allow unrelated histories", "fatal refusing to merge", "git pull origin main error", "git merge two repos", "git init push error", "github first commit merge", "git unrelated histories fix"]
draft: false
schema_json: >
  {
    "@context": "https://schema.org",
    "@type": "TechArticle",
    "name": "ИСПРАВЛЕНИЕ: fatal: refusing to merge unrelated histories",
    "description": "Как исправить ошибку Git refusing to merge unrelated histories при объединении независимых репозиториев.",
    "proficiencyLevel": "Beginner",
    "inLanguage": "ru"
  }
---

## Ошибка

Вы пытаетесь выполнить pull из удалённого репозитория или слить ветку, а Git отказывает:

```
fatal: refusing to merge unrelated histories
```

Обычно это происходит, когда вы выполняете:

```bash
git pull origin main
```

И локальный и удалённый репозитории не имеют общего коммита-предка — Git видит их как два совершенно отдельных проекта и отказывается объединять их автоматически.

---

## Быстрое Исправление

Добавьте флаг `--allow-unrelated-histories`, чтобы заставить Git объединить две независимые истории:

```bash
# Pull and merge unrelated histories
git pull origin main --allow-unrelated-histories
```

Или если вы сливаете ветку:

```bash
# Merge a branch with unrelated history
git merge other-branch --allow-unrelated-histories
```

Git попытается выполнить слияние. Если есть конфликты файлов, разрешите их обычным способом:

```bash
# Check which files conflict
git status

# After resolving conflicts in your editor
git add .
git commit -m "Merge unrelated histories"
```

---

## Почему Это Происходит

Эта ошибка возникает, когда два репозитория Git не имеют общей истории коммитов. Наиболее распространённые сценарии:

### Сценарий 1: Новый репозиторий с конфликтом README

Вы создали локальный репозиторий с помощью `git init` и сделали несколько коммитов. Затем создали репозиторий на GitHub **с README.md** (или `.gitignore`, или `LICENSE`). Теперь при попытке pull удалённый репозиторий имеет корневой коммит, о котором ваш локальный репозиторий ничего не знает.

```bash
# This is the classic cause:
mkdir my-project && cd my-project
git init
echo "hello" > app.py
git add . && git commit -m "first commit"
git remote add origin https://github.com/user/my-project.git
git pull origin main   # ERROR: unrelated histories
```

**Предотвращение:** При создании нового репозитория на GitHub для отправки существующего локального проекта создавайте удалённый репозиторий **без** инициализации (без README, без .gitignore, без лицензии). Затем делайте push напрямую.

### Сценарий 2: Объединение двух независимых репозиториев

Вы хотите объединить два отдельных проекта в один репозиторий. Поскольку они были созданы независимо, у них совершенно разные деревья коммитов.

### Сценарий 3: Переписанная история

Кто-то выполнил `git rebase` или `git filter-branch` на удалённом репозитории, что переписало корневые коммиты. История удалённого репозитория больше не имеет общего предка с вашей локальной копией.

---

## Это Безопасно?

Да — `--allow-unrelated-histories` просто говорит Git продолжить слияние, даже если две ветки не имеют общей базы. Он ничего не удаляет, не перезаписывает и не делает rebase. Если есть конфликтующие файлы, Git пометит их как конфликты и позволит вам разрешить их вручную, точно так же, как при обычном слиянии.

Флаг был добавлен в **Git 2.9** (июнь 2016). До этой версии Git разрешал слияния без общей истории по умолчанию.

---

## Связанные Ресурсы

Освойте продвинутые слияния, rebase и разрешение конфликтов с нашей [Git Protocol Cheatsheet](/cheatsheets/git-commands-for-hackers/) — каждая команда Git, которая нужна разработчику, организованная по рабочим процессам.
