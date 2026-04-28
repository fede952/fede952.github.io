---
title: "Git-Protokoll: Die Wesentliche Befehlsreferenz"
description: "Ein taktisches Git-Cheatsheet über Notfallkorrekturen, GPG-Signierung, Branch-Operationen und erweiterte Workflows. Die Befehle, die jeder Entwickler und Hacker auswendig kennen muss."
date: 2026-02-10
tags: ["git", "cheatsheet", "version-control", "developer-tools"]
keywords: ["git befehle cheatsheet", "git commit rückgängig", "git gpg signierung", "git branch befehle", "git reset anleitung", "git rebase tutorial", "erweiterte git befehle", "git für hacker"]
draft: false
schema_json: >
  {
    "@context": "https://schema.org",
    "@type": "TechArticle",
    "name": "Git-Protokoll: Die Wesentliche Befehlsreferenz",
    "description": "Umfassendes Git-Befehls-Cheatsheet über Notfallkorrekturen, GPG-Signierung, Branch-Operationen und erweiterte Workflows.",
    "proficiencyLevel": "Intermediate",
    "inLanguage": "de"
  }
---

## $ System_Init

Jede Operation hinterlässt eine Spur. Jeder Commit ist ein Checkpoint. Git ist nicht nur Versionskontrolle — es ist das forensische Rückgrat jedes Softwareprojekts. Dieses Feldhandbuch enthält die Befehle, die Sie täglich verwenden werden, und diejenigen, die Sie retten, wenn alles zusammenbricht.

Befehle sind nach Missionstyp organisiert. Führen Sie sie präzise aus.

---

## $ Emergency_Fixes

Wenn ein Deployment schiefgeht und die Zeitlinie neu geschrieben werden muss.

### Den letzten Commit rückgängig machen (Änderungen in Staging behalten)

```bash
# Macht den letzten Commit rückgängig, behält aber Ihre Änderungen im Staging-Bereich
git reset --soft HEAD~1
```

### Den letzten Commit rückgängig machen (aus Staging entfernen)

```bash
# Macht den letzten Commit rückgängig und verschiebt Änderungen zurück ins Arbeitsverzeichnis
git reset --mixed HEAD~1
```

### Nuklearer Reset (alle lokalen Änderungen zerstören)

```bash
# WARNUNG: Dies zerstört dauerhaft alle nicht committeten Arbeiten
git reset --hard HEAD~1
```

### Die letzte Commit-Nachricht ändern

```bash
# Korrigiert einen Tippfehler in Ihrer letzten Commit-Nachricht ohne einen neuen Commit zu erstellen
git commit --amend -m "korrigierte commit nachricht"
```

### Einen gelöschten Branch wiederherstellen

```bash
# Finden Sie den verlorenen Commit-Hash im Reflog
git reflog

# Erstellen Sie den Branch aus dem wiederhergestellten Hash neu
git checkout -b recovered-branch abc1234
```

### Einen Commit rückgängig machen ohne die Historie zu überschreiben

```bash
# Erstellt einen neuen Commit, der einen bestimmten Commit rückgängig macht (sicher für gemeinsame Branches)
git revert <commit-hash>
```

---

## $ Stealth_Mode

Kryptographische Signierung und Identitätsverifizierung. Beweisen Sie, dass Ihre Commits authentisch sind.

### GPG-Signierung konfigurieren

```bash
# Listen Sie Ihre verfügbaren GPG-Schlüssel auf
gpg --list-secret-keys --keyid-format=long

# Sagen Sie Git, welchen Schlüssel er verwenden soll
git config --global user.signingkey YOUR_KEY_ID

# Aktivieren Sie die automatische Signierung für alle Commits
git config --global commit.gpgsign true
```

### Einen einzelnen Commit signieren

```bash
# Signieren Sie manuell einen bestimmten Commit
git commit -S -m "signed: verified deployment"
```

### Commit-Signaturen verifizieren

```bash
# Überprüfen Sie die Signatur des letzten Commits
git log --show-signature -1

# Verifizieren Sie Signaturen im gesamten Log
git log --pretty="format:%h %G? %aN %s"
```

### Tags für Releases signieren

```bash
# Erstellen Sie einen signierten Release-Tag
git tag -s v1.0.0 -m "Release v1.0.0 - signed"

# Verifizieren Sie einen signierten Tag
git tag -v v1.0.0
```

---

## $ Branch_Operations

Taktisches Branch-Management für parallele Entwicklung.

### Einen neuen Branch erstellen und zu ihm wechseln

```bash
# Erstellen Sie einen Feature-Branch und wechseln Sie mit einem Befehl zu ihm
git checkout -b feature/new-module
```

### Alle Branches auflisten (lokal und remote)

```bash
# Zeigen Sie alle Branches einschließlich Remote-Tracking-Branches an
git branch -a
```

### Einen Branch sicher löschen

```bash
# Löschen Sie einen lokalen Branch (nur wenn vollständig gemerged)
git branch -d feature/old-module

# Erzwingen Sie das Löschen eines lokalen Branches (auch wenn nicht gemerged)
git branch -D feature/abandoned-experiment
```

### Einen Remote-Branch löschen

```bash
# Entfernen Sie einen Branch aus dem Remote-Repository
git push origin --delete feature/old-module
```

### Rebase auf main (lineare Historie)

```bash
# Wenden Sie Ihre Branch-Commits auf den neuesten main an
git checkout feature/my-work
git rebase main
```

### Interaktiver Rebase (squash, neu ordnen, bearbeiten)

```bash
# Schreiben Sie die letzten 3 Commits interaktiv um
git rebase -i HEAD~3
```

---

## $ Reconnaissance

Inspizieren Sie den Repository-Status, bevor Sie Entscheidungen treffen.

### Kompaktes Log mit Graph anzeigen

```bash
# Einzeiliges Log mit grafischer Branch-Visualisierung
git log --oneline --graph --all --decorate
```

### Änderungen im Staging-Bereich anzeigen

```bash
# Vergleichen Sie gestagede Änderungen mit dem letzten Commit
git diff --cached
```

### Blame für eine Datei (finden Sie heraus, wer jede Zeile geändert hat)

```bash
# Zeigen Sie Autor und Commit für jede Zeile in einer Datei an
git blame path/to/file.py
```

### In Commit-Nachrichten suchen

```bash
# Finden Sie Commits, die ein bestimmtes Schlüsselwort in der Nachricht enthalten
git log --grep="bugfix" --oneline
```

### Herausfinden, welcher Commit einen Bug eingeführt hat

```bash
# Binäre Suche durch Commits, um die fehlerverursachende Änderung zu finden
git bisect start
git bisect bad          # Der aktuelle Commit ist defekt
git bisect good abc1234 # Dieser alte Commit funktionierte
# Git wird Commits für Sie zum Testen auschecken
```

---

## $ Stash_Operations

Legen Sie Arbeit vorübergehend beiseite, ohne zu committen.

### Aktuelle Änderungen stashen

```bash
# Speichern Sie nicht committete Änderungen in einem temporären Stack
git stash push -m "work in progress: auth module"
```

### Alle Stashes auflisten

```bash
# Zeigen Sie alle gestashten Einträge an
git stash list
```

### Einen Stash anwenden und entfernen

```bash
# Stellen Sie den neuesten Stash wieder her und entfernen Sie ihn vom Stack
git stash pop

# Stellen Sie einen bestimmten Stash nach Index wieder her
git stash apply stash@{2}
```

### Einen Branch aus einem Stash erstellen

```bash
# Verwandeln Sie einen Stash in einen richtigen Feature-Branch
git stash branch feature/from-stash stash@{0}
```

---

## $ Advanced_Protocols

Leistungsstarke Befehle für komplexe Szenarien.

### Cherry-pick eines Commits von einem anderen Branch

```bash
# Wenden Sie einen bestimmten Commit von einem Branch auf Ihren aktuellen Branch an
git cherry-pick <commit-hash>
```

### Nicht verfolgte Dateien bereinigen

```bash
# Vorschau, was gelöscht wird
git clean -n

# Löschen Sie nicht verfolgte Dateien und Verzeichnisse
git clean -fd
```

### Eine Patch-Datei erstellen

```bash
# Exportieren Sie den letzten Commit als portable Patch-Datei
git format-patch -1 HEAD

# Wenden Sie eine Patch-Datei an
git am < patch-file.patch
```

### Flacher Klon (Bandbreite sparen)

```bash
# Klonen Sie nur den neuesten Commit (keine vollständige Historie)
git clone --depth 1 https://github.com/user/repo.git
```
