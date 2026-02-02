---
title: "Schluss mit KI-Abos: DeepSeek & Llama 3 Kostenlos Lokal Ausführen"
date: 2026-02-02
description: "Erfahren Sie, wie Sie leistungsstarke KI-Modelle wie DeepSeek und Llama 3 mit Ollama kostenlos auf Ihrem eigenen PC ausführen. Vollständige Privatsphäre, keine monatlichen Kosten, funktioniert offline."
tags: ["AI", "Ollama", "Privacy", "Tutorial", "LocalLLM"]
categories: ["Guides", "Artificial Intelligence"]
author: "Federico Sella"
draft: false
---

Sie brauchen kein 20$-Monatsabo, um einen leistungsfähigen KI-Assistenten zu nutzen. Mit einem kostenlosen Open-Source-Tool namens **Ollama** können Sie hochmoderne Sprachmodelle — darunter **Metas Llama 3** und **DeepSeek-R1** — direkt auf Ihrem eigenen Computer ausführen. Keine Cloud. Kein Konto. Keine Daten, die jemals Ihren Rechner verlassen.

Diese Anleitung führt Sie in weniger als 10 Minuten durch die gesamte Einrichtung.

## Warum KI Lokal Ausführen?

### Vollständige Privatsphäre

Wenn Sie einen Cloud-KI-Dienst nutzen, wird jeder Prompt, den Sie eingeben, an einen Remote-Server gesendet. Das umfasst Code-Snippets, Geschäftsideen, persönliche Fragen — alles. Mit einem **lokalen LLM** bleiben Ihre Gespräche auf Ihrer Hardware. Punkt.

### Keine Monatlichen Kosten

ChatGPT Plus kostet 20$/Monat. Claude Pro kostet 20$/Monat. GitHub Copilot kostet 10$/Monat. Ein lokales Modell kostet **nichts** nach dem ersten Download. Die Modelle sind Open-Source und kostenlos.

### Funktioniert Offline

Im Flugzeug? In einer Hütte ohne WLAN? Egal. Ein lokales Modell läuft vollständig auf Ihrer CPU und RAM — keine Internetverbindung erforderlich.

---

## Voraussetzungen

Sie brauchen weder eine GPU noch eine High-End-Workstation. Hier das Minimum:

- **Betriebssystem:** Windows 10/11, macOS 12+ oder Linux
- **RAM:** Mindestens 8 GB (16 GB empfohlen für größere Modelle)
- **Festplattenspeicher:** ~5 GB frei für die Anwendung und ein Modell
- **Optional:** Eine dedizierte GPU (NVIDIA/AMD) beschleunigt die Inferenz, ist aber **nicht erforderlich**

---

## Schritt 1: Ollama Herunterladen und Installieren

**Ollama** ist eine leichtgewichtige Laufzeitumgebung, die LLMs mit einem einzigen Befehl herunterlädt, verwaltet und ausführt. Die Installation ist auf jeder Plattform unkompliziert.

### Windows

1. Besuchen Sie [ollama.com](https://ollama.com) und klicken Sie auf **Download for Windows**.
2. Führen Sie den Installer aus — das dauert etwa eine Minute.
3. Ollama läuft nach der Installation automatisch im Hintergrund.

### macOS

Sie haben zwei Möglichkeiten:

```bash
# Option A: Homebrew (empfohlen)
brew install ollama

# Option B: Direkter Download
# Besuchen Sie https://ollama.com und laden Sie die .dmg herunter
```

### Linux

Ein einziger Befehl erledigt alles:

```bash
curl -fsSL https://ollama.com/install.sh | sh
```

Nach der Installation überprüfen Sie, ob es funktioniert:

```bash
ollama --version
```

Sie sollten eine Versionsnummer in Ihrem Terminal sehen.

---

## Schritt 2: Ihr Erstes Modell Ausführen — Der Magische Befehl

Dies ist der Moment. Öffnen Sie ein Terminal und geben Sie ein:

```bash
ollama run llama3
```

Das war's. Ollama lädt beim ersten Start das **Llama 3 8B**-Modell (~4,7 GB) herunter und bringt Sie dann in eine interaktive Chat-Sitzung direkt in Ihrem Terminal:

```
>>> Wer bist du?
Ich bin Llama, ein großes Sprachmodell, trainiert von Meta.
Wie kann ich Ihnen heute helfen?

>>> Schreibe eine Python-Funktion, die prüft, ob eine Zahl eine Primzahl ist.
def is_prime(n):
    if n < 2:
        return False
    for i in range(2, int(n**0.5) + 1):
        if n % i == 0:
            return False
    return True
```

### Probieren Sie DeepSeek-R1 für Denkaufgaben

**DeepSeek-R1** glänzt bei Mathematik, Logik und schrittweiser Problemlösung:

```bash
ollama run deepseek-r1
```

### Andere Beliebte Modelle

| Modell | Befehl | Ideal Für |
|---|---|---|
| Llama 3 8B | `ollama run llama3` | Allgemeiner Chat, Programmierung |
| DeepSeek-R1 8B | `ollama run deepseek-r1` | Mathematik, Logik, Schlussfolgerung |
| Mistral 7B | `ollama run mistral` | Schnell, effizienter Allrounder |
| Gemma 2 9B | `ollama run gemma2` | Googles offenes Modell |
| Qwen 2.5 7B | `ollama run qwen2.5` | Mehrsprachige Aufgaben |

Führen Sie `ollama list` aus, um Ihre heruntergeladenen Modelle zu sehen, und `ollama rm <modell>` um eines zu löschen und Speicher freizugeben.

---

## Schritt 3: Chat-Interface mit Open WebUI Hinzufügen (Optional)

Das Terminal funktioniert, aber wenn Sie eine polierte **ChatGPT-ähnliche Oberfläche** wollen, installieren Sie **Open WebUI**. Der schnellste Weg ist Docker:

```bash
docker run -d -p 3000:8080 --add-host=host.docker.internal:host-gateway \
  -v open-webui:/app/backend/data --name open-webui \
  --restart always ghcr.io/open-webui/open-webui:main
```

Dann öffnen Sie [http://localhost:3000](http://localhost:3000) in Ihrem Browser. Sie erhalten eine vertraute Chat-Oberfläche mit Gesprächsverlauf, Modellwechsel, Datei-Upload und mehr — alles verbunden mit Ihrer lokalen Ollama-Instanz.

> **Kein Docker?** Es gibt andere leichtgewichtige Frontends wie [Chatbox](https://chatboxai.app) (Desktop-App) oder [Ollama Web UI](https://github.com/ollama-webui/ollama-webui), die kein Docker benötigen.

---

## Lokale KI vs. Cloud-KI: Der Vollständige Vergleich

| Merkmal | Lokale KI (Ollama) | Cloud-KI (ChatGPT, Claude) |
|---|---|---|
| **Privatsphäre** | Ihre Daten verlassen nie Ihren PC | Daten werden an Remote-Server gesendet |
| **Kosten** | Vollständig kostenlos | 20$/Monat für Premium-Stufen |
| **Internet Erforderlich** | Nein — funktioniert vollständig offline | Ja — immer |
| **Geschwindigkeit** | Abhängig von Ihrer Hardware | Schnell (serverseitige GPUs) |
| **Modellqualität** | Exzellent (Llama 3, DeepSeek) | Exzellent (GPT-4o, Claude) |
| **Einrichtungsaufwand** | Ein Befehl | Konto erstellen |
| **Anpassbarkeit** | Volle Kontrolle, Fine-Tuning | Begrenzt |
| **Datenspeicherung** | Sie kontrollieren alles | Richtlinie des Anbieters gilt |

**Fazit:** Cloud-Modelle haben bei den größten Aufgaben noch einen Vorsprung in der Rohleistung, aber für die tägliche Hilfe beim Programmieren, Schreiben, Brainstorming und Q&A sind lokale Modelle **mehr als ausreichend** — und sie sind kostenlos und privat.

---

## Schlussfolgerung

Eine lokale KI auszuführen ist kein Nischen-Hobby mehr für Forscher mit teuren GPUs. Dank **Ollama** und dem Open-Source-Modell-Ökosystem kann jeder mit einem modernen Laptop in weniger als 10 Minuten einen privaten, kostenlosen, offline-fähigen KI-Assistenten haben.

Die Befehle zum Merken:

```bash
# Installieren (Linux)
curl -fsSL https://ollama.com/install.sh | sh

# Ein Modell ausführen
ollama run llama3

# Ihre Modelle auflisten
ollama list
```

Probieren Sie es aus. Sobald Sie die Geschwindigkeit und Privatsphäre eines lokalen LLM erlebt haben, könnten Sie feststellen, dass Sie die Cloud immer weniger nutzen.

> Müssen Sie beim Programmieren neben Ihrer lokalen KI konzentriert bleiben? Probieren Sie unseren [ZenFocus Ambient-Mixer und Pomodoro-Timer](/de/tools/zen-focus/) — ein weiteres Tool, das vollständig in Ihrem Browser ohne jegliches Tracking läuft.
