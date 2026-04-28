---
title: "Git Disaster Recovery: Fehler Ruckgangig Machen und Historie Reparieren"
description: "Das Notfall-Kit fur Entwickler. Lernen Sie, Commits ruckgangig zu machen, Merge-Konflikte zu losen, geloschte Branches wiederherzustellen und git rebase vs merge zu meistern."
date: 2026-02-13
tags: ["git", "cheatsheet", "devops", "version-control"]
keywords: ["git undo commit", "git reset hard vs soft", "recover deleted branch", "git rebase tutorial", "fix merge conflict", "git cherry-pick"]
draft: false
schema_json: >
  {
    "@context": "https://schema.org",
    "@type": "TechArticle",
    "name": "Git Disaster Recovery: Fehler Ruckgangig Machen und Historie Reparieren",
    "description": "Das Notfall-Kit fur Entwickler. Lernen Sie, Commits ruckgangig zu machen, Merge-Konflikte zu losen, geloschte Branches wiederherzustellen und git rebase vs merge zu meistern.",
    "proficiencyLevel": "Intermediate",
    "inLanguage": "de"
  }
---

## Anderungen Ruckgangig Machen

Die drei Saulen von "Ich habe Mist gebaut": reset, revert und restore. Jeder hat einen anderen Wirkungsbereich und Gefahrenstufe.

### git restore — Nicht gestagete Anderungen verwerfen

```bash
# Anderungen in einer einzelnen Datei verwerfen (nur Arbeitsverzeichnis)
git restore file.txt

# ALLE nicht gestageten Anderungen verwerfen
git restore .

# Eine Datei aus dem Staging entfernen (Anderungen im Arbeitsverzeichnis behalten)
git restore --staged file.txt

# Eine Datei auf die Version eines bestimmten Commits wiederherstellen
git restore --source=abc1234 file.txt
```

### git reset — HEAD zurucksetzen

```bash
# Soft Reset: Commit ruckgangig machen, Anderungen bleiben gestaget
git reset --soft HEAD~1

# Mixed Reset (Standard): Commit ruckgangig machen, Staging aufheben, Dateien behalten
git reset HEAD~1

# Hard Reset: Commit ruckgangig machen, ALLE Anderungen dauerhaft LOSCHEN
git reset --hard HEAD~1

# Auf einen bestimmten Commit zurucksetzen
git reset --hard abc1234
```

> **--soft** behalt alles gestaget. **--mixed** hebt das Staging auf, behalt aber die Dateien. **--hard** zerstort alles. Im Zweifel `--soft` verwenden.

### git revert — Einen Commit sicher ruckgangig machen (offentliche Historie)

```bash
# Einen neuen Commit erstellen, der einen bestimmten Commit ruckgangig macht
git revert abc1234

# Revert ohne automatischen Commit (nur Anderungen stagen)
git revert --no-commit abc1234

# Einen Merge-Commit ruckgangig machen (Parent #1 behalten)
git revert -m 1 <merge-commit-hash>
```

> Verwenden Sie `revert` statt `reset` bei gemeinsam genutzten Branches — es schreibt die Historie nicht um.

---

## Historie Umschreiben

Fur den Fall, dass Ihre Commit-Nachrichten peinlich sind oder Ihre Branch-Historie ein Chaos ist.

### git commit --amend

```bash
# Die letzte Commit-Nachricht andern
git commit --amend -m "better message"

# Vergessene Dateien zum letzten Commit hinzufugen
git add forgotten-file.txt
git commit --amend --no-edit
```

### git rebase -i (Interaktiver Rebase)

```bash
# Die letzten 3 Commits umschreiben
git rebase -i HEAD~3
```

Im Editor konnen Sie:

| Befehl   | Wirkung                                |
|----------|----------------------------------------|
| `pick`   | Commit unverandert beibehalten         |
| `reword` | Commit-Nachricht andern                |
| `edit`   | Anhalten, um den Commit zu bearbeiten  |
| `squash` | Mit vorherigem Commit zusammenfuhren   |
| `fixup`  | Wie squash, aber Nachricht verwerfen   |
| `drop`   | Den Commit vollstandig loschen         |

```bash
# Aktuellen Branch auf main rebasen (lineare Historie)
git rebase main

# Nach dem Losen von Konflikten fortfahren
git rebase --continue

# Einen fehlgeschlagenen Rebase abbrechen
git rebase --abort
```

> **Rebase vs Merge:** Rebase erzeugt eine lineare Historie (sauberere Logs). Merge bewahrt die Branch-Topologie (sicherer fur gemeinsam genutzte Branches). Rebasen Sie niemals Commits, die andere bereits gepullt haben.

---

## Wiederherstellung

Wenn alles brennt, sind diese Befehle Ihr Feuerloscher.

### git reflog — Der Lebensretter

Das Reflog zeichnet jede HEAD-Bewegung auf. Selbst nach einem Hard Reset sind Ihre Commits noch vorhanden.

```bash
# Das Reflog anzeigen (alle letzten HEAD-Positionen)
git reflog

# Beispielausgabe:
# abc1234 HEAD@{0}: reset: moving to HEAD~3
# def5678 HEAD@{1}: commit: add feature X
# 9ab0123 HEAD@{2}: commit: fix login bug

# Wiederherstellen durch Zurucksetzen auf einen Reflog-Eintrag
git reset --hard HEAD@{1}

# Oder einen verlorenen Commit per Cherry-Pick holen
git cherry-pick def5678
```

### git fsck — Verwaiste Objekte finden

```bash
# Unerreichbare Commits und Blobs finden
git fsck --unreachable

# Speziell verlorene Commits finden
git fsck --lost-found
# Ergebnisse werden in .git/lost-found/ gespeichert
```

### Einen geloschten Branch wiederherstellen

```bash
# Schritt 1: Den letzten Commit des geloschten Branches finden
git reflog | grep "branch-name"
# Oder nach der Commit-Nachricht suchen
git reflog | grep "feature I was working on"

# Schritt 2: Den Branch an diesem Commit neu erstellen
git branch recovered-branch abc1234

# Alternative: In einem Schritt finden und wiederherstellen
git checkout -b recovered-branch HEAD@{5}
```

---

## Haufige Katastrophen-Szenarien

### "Ich habe auf dem falschen Branch committet"

```bash
# Schritt 1: Commit-Hash notieren
git log --oneline -1
# abc1234 accidental commit

# Schritt 2: Commit auf dem falschen Branch ruckgangig machen (Anderungen behalten)
git reset --soft HEAD~1

# Schritt 3: Stashen, wechseln und anwenden
git stash
git checkout correct-branch
git stash pop
git add . && git commit -m "feature in the right place"
```

### "Ich mochte eine Datei nicht mehr tracken, sie aber lokal behalten"

```bash
# Aus dem Git-Tracking entfernen, Datei aber auf der Festplatte behalten
git rm --cached secret-config.env

# Zur .gitignore hinzufugen, um zukunftiges Tracking zu verhindern
echo "secret-config.env" >> .gitignore
git add .gitignore
git commit -m "stop tracking secret-config.env"
```

### "Ich muss einen Push ruckgangig machen"

```bash
# Sichere Methode: Den Commit reverten (erstellt neuen Commit)
git revert abc1234
git push

# Nukleare Option: Force Push (GEFAHRLICH bei gemeinsam genutzten Branches)
git reset --hard HEAD~1
git push --force-with-lease
```

### "Mein Merge hat uberall Konflikte"

```bash
# Anzeigen, welche Dateien Konflikte haben
git status

# In jeder betroffenen Datei nach Konflikt-Markern suchen:
# <<<<<<< HEAD
# your changes
# =======
# their changes
# >>>>>>> branch-name

# Nach dem Losen aller Konflikte:
git add .
git commit

# Oder den Merge komplett abbrechen
git merge --abort
```

### git cherry-pick — Bestimmte Commits ubernehmen

```bash
# Einen einzelnen Commit von einem anderen Branch anwenden
git cherry-pick abc1234

# Mehrere Commits anwenden
git cherry-pick abc1234 def5678

# Cherry-Pick ohne Commit (nur stagen)
git cherry-pick --no-commit abc1234
```

---

## Kurzreferenz-Tabelle

| Situation | Befehl |
|-----------|--------|
| Letzten Commit ruckgangig machen (Anderungen behalten) | `git reset --soft HEAD~1` |
| Letzten Commit ruckgangig machen (Anderungen loschen) | `git reset --hard HEAD~1` |
| Einen gepushten Commit ruckgangig machen | `git revert <hash>` |
| Datei-Anderungen verwerfen | `git restore <file>` |
| Eine Datei aus dem Staging entfernen | `git restore --staged <file>` |
| Geloschten Branch wiederherstellen | `git reflog` + `git branch name <hash>` |
| Letzte Commit-Nachricht andern | `git commit --amend -m "new msg"` |
| Letzte N Commits zusammenfassen | `git rebase -i HEAD~N` |
| Commit auf richtigen Branch verschieben | `git reset --soft HEAD~1` + stash + switch |
| Datei nicht mehr tracken | `git rm --cached <file>` |
