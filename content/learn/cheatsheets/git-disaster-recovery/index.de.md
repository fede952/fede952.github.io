---
title: "Git Disaster Recovery: Fehler Rückgängig Machen und Historie Reparieren"
description: "Das Notfall-Kit für Entwickler. Lernen Sie, Commits rückgängig zu machen, Merge-Konflikte zu lösen, gelöschte Branches wiederherzustellen und git rebase vs merge zu meistern."
date: 2026-02-13
tags: ["git", "cheatsheet", "devops", "version-control"]
keywords: ["git undo commit", "git reset hard vs soft", "recover deleted branch", "git rebase tutorial", "fix merge conflict", "git cherry-pick"]
draft: false
proficiency: "Intermediate"
aliases: ["/cheatsheets/git-disaster-recovery/"]
---

## Änderungen rückgängig machen

Die drei Säulen von "Ich habe Mist gebaut": reset, revert und restore. Jeder hat einen anderen Wirkungsbereich und Gefahrenstufe.

### git restore — Nicht gestagete Änderungen verwerfen

```bash
# Änderungen in einer einzelnen Datei verwerfen (nur Arbeitsverzeichnis)
git restore file.txt

# ALLE nicht gestageten Änderungen verwerfen
git restore .

# Eine Datei aus dem Staging entfernen (Änderungen im Arbeitsverzeichnis behalten)
git restore --staged file.txt

# Eine Datei auf die Version eines bestimmten Commits wiederherstellen
git restore --source=abc1234 file.txt
```

### git reset — HEAD zurücksetzen

```bash
# Soft Reset: Commit rückgängig machen, Änderungen bleiben gestaget
git reset --soft HEAD~1

# Mixed Reset (Standard): Commit rückgängig machen, Staging aufheben, Dateien behalten
git reset HEAD~1

# Hard Reset: Commit rückgängig machen, ALLE Änderungen dauerhaft LÖSCHEN
git reset --hard HEAD~1

# Auf einen bestimmten Commit zurücksetzen
git reset --hard abc1234
```

> **--soft** behält alles gestaget. **--mixed** hebt das Staging auf, behält aber die Dateien. **--hard** zerstört alles. Im Zweifel `--soft` verwenden.

### git revert — Einen Commit sicher rückgängig machen (öffentliche Historie)

```bash
# Einen neuen Commit erstellen, der einen bestimmten Commit rückgängig macht
git revert abc1234

# Revert ohne automatischen Commit (nur Änderungen stagen)
git revert --no-commit abc1234

# Einen Merge-Commit rückgängig machen (Parent #1 behalten)
git revert -m 1 <merge-commit-hash>
```

> Verwenden Sie `revert` statt `reset` bei gemeinsam genutzten Branches — es schreibt die Historie nicht um.

---

## Historie umschreiben

Für den Fall, dass Ihre Commit-Nachrichten peinlich sind oder Ihre Branch-Historie ein Chaos ist.

### git commit --amend

```bash
# Die letzte Commit-Nachricht ändern
git commit --amend -m "better message"

# Vergessene Dateien zum letzten Commit hinzufügen
git add forgotten-file.txt
git commit --amend --no-edit
```

### git rebase -i (Interaktiver Rebase)

```bash
# Die letzten 3 Commits umschreiben
git rebase -i HEAD~3
```

Im Editor können Sie:

| Befehl   | Wirkung                                |
|----------|----------------------------------------|
| `pick`   | Commit unverändert beibehalten         |
| `reword` | Commit-Nachricht ändern                |
| `edit`   | Anhalten, um den Commit zu bearbeiten  |
| `squash` | Mit vorherigem Commit zusammenführen   |
| `fixup`  | Wie squash, aber Nachricht verwerfen   |
| `drop`   | Den Commit vollständig löschen         |

```bash
# Aktuellen Branch auf main rebasen (lineare Historie)
git rebase main

# Nach dem Lösen von Konflikten fortfahren
git rebase --continue

# Einen fehlgeschlagenen Rebase abbrechen
git rebase --abort
```

> **Rebase vs Merge:** Rebase erzeugt eine lineare Historie (sauberere Logs). Merge bewahrt die Branch-Topologie (sicherer für gemeinsam genutzte Branches). Rebasen Sie niemals Commits, die andere bereits gepullt haben.

---

## Verlorene Commits und Branches wiederherstellen

Wenn alles brennt, sind diese Befehle Ihr Feuerlöscher.

### git reflog — Der Lebensretter

Das Reflog zeichnet jede HEAD-Bewegung auf. Selbst nach einem Hard Reset sind Ihre Commits noch vorhanden.

```bash
# Das Reflog anzeigen (alle letzten HEAD-Positionen)
git reflog

# Beispielausgabe:
# abc1234 HEAD@{0}: reset: moving to HEAD~3
# def5678 HEAD@{1}: commit: add feature X
# 9ab0123 HEAD@{2}: commit: fix login bug

# Wiederherstellen durch Zurücksetzen auf einen Reflog-Eintrag
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

### Einen gelöschten Branch wiederherstellen

```bash
# Schritt 1: Den letzten Commit des gelöschten Branches finden
git reflog | grep "branch-name"
# Oder nach der Commit-Nachricht suchen
git reflog | grep "feature I was working on"

# Schritt 2: Den Branch an diesem Commit neu erstellen
git branch recovered-branch abc1234

# Alternative: In einem Schritt finden und wiederherstellen
git checkout -b recovered-branch HEAD@{5}
```

---

## Häufige Katastrophen-Szenarien

### "Ich habe auf dem falschen Branch committet"

```bash
# Schritt 1: Commit-Hash notieren
git log --oneline -1
# abc1234 accidental commit

# Schritt 2: Commit auf dem falschen Branch rückgängig machen (Änderungen behalten)
git reset --soft HEAD~1

# Schritt 3: Stashen, wechseln und anwenden
git stash
git checkout correct-branch
git stash pop
git add . && git commit -m "feature in the right place"
```

### "Ich möchte eine Datei nicht mehr tracken, sie aber lokal behalten"

```bash
# Aus dem Git-Tracking entfernen, Datei aber auf der Festplatte behalten
git rm --cached secret-config.env

# Zur .gitignore hinzufügen, um zukünftiges Tracking zu verhindern
echo "secret-config.env" >> .gitignore
git add .gitignore
git commit -m "stop tracking secret-config.env"
```

### "Ich muss einen Push rückgängig machen"

```bash
# Sichere Methode: Den Commit reverten (erstellt neuen Commit)
git revert abc1234
git push

# Nukleare Option: Force Push (GEFÄHRLICH bei gemeinsam genutzten Branches)
git reset --hard HEAD~1
git push --force-with-lease
```

### "Mein Merge hat überall Konflikte"

```bash
# Anzeigen, welche Dateien Konflikte haben
git status

# In jeder betroffenen Datei nach Konflikt-Markern suchen:
# <<<<<<< HEAD
# your changes
# =======
# their changes
# >>>>>>> branch-name

# Nach dem Lösen aller Konflikte:
git add .
git commit

# Oder den Merge komplett abbrechen
git merge --abort
```

### git cherry-pick — Bestimmte Commits übernehmen

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
| Letzten Commit rückgängig machen (Änderungen behalten) | `git reset --soft HEAD~1` |
| Letzten Commit rückgängig machen (Änderungen löschen) | `git reset --hard HEAD~1` |
| Einen gepushten Commit rückgängig machen | `git revert <hash>` |
| Datei-Änderungen verwerfen | `git restore <file>` |
| Eine Datei aus dem Staging entfernen | `git restore --staged <file>` |
| Gelöschten Branch wiederherstellen | `git reflog` + `git branch name <hash>` |
| Letzte Commit-Nachricht ändern | `git commit --amend -m "new msg"` |
| Letzte N Commits zusammenfassen | `git rebase -i HEAD~N` |
| Commit auf richtigen Branch verschieben | `git reset --soft HEAD~1` + stash + switch |
| Datei nicht mehr tracken | `git rm --cached <file>` |
