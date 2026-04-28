---
title: "LÖSUNG: fatal: refusing to merge unrelated histories"
description: "Beheben Sie den Git-Fehler 'refusing to merge unrelated histories' beim Pullen oder Mergen. Verstehen Sie, warum er auftritt und wie Sie zwei unabhängige Repositories sicher zusammenführen."
date: 2026-02-11
tags: ["git", "debug", "devops", "version-control"]
keywords: ["refusing to merge unrelated histories", "git pull unrelated histories", "git merge unrelated histories", "allow unrelated histories", "fatal refusing to merge", "git pull origin main error", "git merge two repos", "git init push error", "github first commit merge", "git unrelated histories fix"]
draft: false
schema_json: >
  {
    "@context": "https://schema.org",
    "@type": "TechArticle",
    "name": "LÖSUNG: fatal: refusing to merge unrelated histories",
    "description": "Wie man den Git-Fehler refusing to merge unrelated histories beim Zusammenführen unabhängiger Repositories behebt.",
    "proficiencyLevel": "Beginner",
    "inLanguage": "de"
  }
---

## Der Fehler

Sie versuchen, von einem Remote-Repository zu pullen oder einen Branch zu mergen und Git verweigert dies:

```
fatal: refusing to merge unrelated histories
```

Dies passiert typischerweise, wenn Sie ausführen:

```bash
git pull origin main
```

Und die lokalen und Remote-Repositories keinen gemeinsamen Vorfahren-Commit haben — Git betrachtet sie als zwei völlig getrennte Projekte und weigert sich, sie automatisch zusammenzuführen.

---

## Die Schnelle Lösung

Fügen Sie das Flag `--allow-unrelated-histories` hinzu, um Git zu zwingen, die zwei unabhängigen Historien zusammenzuführen:

```bash
# Pull and merge unrelated histories
git pull origin main --allow-unrelated-histories
```

Oder wenn Sie einen Branch mergen:

```bash
# Merge a branch with unrelated history
git merge other-branch --allow-unrelated-histories
```

Git wird den Merge versuchen. Wenn es Dateikonflikte gibt, lösen Sie diese normal auf:

```bash
# Check which files conflict
git status

# After resolving conflicts in your editor
git add .
git commit -m "Merge unrelated histories"
```

---

## Warum Das Passiert

Dieser Fehler tritt auf, wenn zwei Git-Repositories keine gemeinsame Commit-Historie teilen. Die häufigsten Szenarien:

### Szenario 1: Neues Repo mit README-Konflikt

Sie haben ein lokales Repository mit `git init` erstellt und einige Commits gemacht. Dann haben Sie ein GitHub-Repo **mit einer README.md** (oder `.gitignore` oder `LICENSE`) erstellt. Wenn Sie nun versuchen zu pullen, hat das Remote einen Root-Commit, den Ihr lokales Repo nicht kennt.

```bash
# This is the classic cause:
mkdir my-project && cd my-project
git init
echo "hello" > app.py
git add . && git commit -m "first commit"
git remote add origin https://github.com/user/my-project.git
git pull origin main   # ERROR: unrelated histories
```

**Vorbeugung:** Wenn Sie ein neues GitHub-Repo erstellen, um ein bestehendes lokales Projekt zu pushen, erstellen Sie das Remote-Repo **ohne** Initialisierung (keine README, kein .gitignore, keine Lizenz). Dann pushen Sie direkt.

### Szenario 2: Zwei unabhängige Repositories zusammenführen

Sie möchten zwei separate Projekte in einem einzigen Repository zusammenführen. Da sie unabhängig erstellt wurden, haben sie völlig unterschiedliche Commit-Bäume.

### Szenario 3: Umgeschriebene Historie

Jemand hat `git rebase` oder `git filter-branch` auf dem Remote ausgeführt, was die Root-Commits umgeschrieben hat. Die Historie des Remotes teilt keinen Vorfahren mehr mit Ihrer lokalen Kopie.

---

## Ist Es Sicher?

Ja — `--allow-unrelated-histories` sagt Git lediglich, mit dem Merge fortzufahren, auch wenn die beiden Branches keine gemeinsame Basis haben. Es löscht, überschreibt oder rebaset nichts. Wenn es widersprüchliche Dateien gibt, markiert Git sie als Konflikte und lässt Sie diese manuell lösen, genau wie bei einem normalen Merge.

Das Flag wurde in **Git 2.9** (Juni 2016) hinzugefügt. Vor dieser Version erlaubte Git unverwandte Merges standardmäßig.

---

## Verwandte Ressourcen

Meistern Sie fortgeschrittene Merges, Rebases und Konfliktlösung mit unserem [Git Protocol Cheatsheet](/cheatsheets/git-commands-for-hackers/) — jeder Git-Befehl, den ein Entwickler braucht, nach Workflow organisiert.
