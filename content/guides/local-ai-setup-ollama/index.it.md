---
title: "Smetti di Pagare per l'AI: Esegui DeepSeek e Llama 3 in Locale Gratis"
date: 2026-02-02
description: "Scopri come eseguire modelli AI potenti come DeepSeek e Llama 3 sul tuo PC gratuitamente con Ollama. Privacy totale, zero costi mensili, funziona offline."
tags: ["AI", "Ollama", "Privacy", "Tutorial", "LocalLLM"]
categories: ["Guides", "Artificial Intelligence"]
author: "Federico Sella"
draft: false
---

Non hai bisogno di un abbonamento da 20$/mese per usare un assistente AI potente. Con uno strumento gratuito e open-source chiamato **Ollama**, puoi eseguire modelli linguistici di ultima generazione — tra cui **Llama 3 di Meta** e **DeepSeek-R1** — direttamente sul tuo computer. Nessun cloud. Nessun account. Nessun dato che lascia mai la tua macchina.

Questa guida ti accompagna nell'intero setup in meno di 10 minuti.

## Perché Eseguire l'AI in Locale?

### Privacy Completa

Quando usi un servizio AI cloud, ogni prompt che digiti viene inviato a un server remoto. Questo include snippet di codice, idee di business, domande personali — tutto. Con un **LLM locale**, le tue conversazioni restano sul tuo hardware. Punto.

### Zero Costi Mensili

ChatGPT Plus costa 20$/mese. Claude Pro costa 20$/mese. GitHub Copilot costa 10$/mese. Un modello locale non costa **nulla** dopo il download iniziale. I modelli sono open-source e gratuiti.

### Funziona Offline

In aereo? In una baita senza Wi-Fi? Non importa. Un modello locale gira interamente su CPU e RAM — non serve connessione internet.

---

## Prerequisiti

Non servono una GPU o una workstation potente. Ecco il minimo:

- **Sistema Operativo:** Windows 10/11, macOS 12+ o Linux
- **RAM:** 8 GB minimo (16 GB consigliati per modelli più grandi)
- **Spazio Disco:** ~5 GB liberi per l'applicazione e un modello
- **Opzionale:** Una GPU dedicata (NVIDIA/AMD) accelera l'inferenza ma **non è necessaria**

---

## Passo 1: Scarica e Installa Ollama

**Ollama** è un runtime leggero che scarica, gestisce ed esegue LLM con un singolo comando. L'installazione è semplice su ogni piattaforma.

### Windows

1. Visita [ollama.com](https://ollama.com) e clicca **Download for Windows**.
2. Esegui l'installer — ci vuole circa un minuto.
3. Ollama si avvia in background automaticamente dopo l'installazione.

### macOS

Hai due opzioni:

```bash
# Opzione A: Homebrew (consigliato)
brew install ollama

# Opzione B: Download diretto
# Visita https://ollama.com e scarica il .dmg
```

### Linux

Un singolo comando fa tutto:

```bash
curl -fsSL https://ollama.com/install.sh | sh
```

Dopo l'installazione, verifica che funzioni:

```bash
ollama --version
```

Dovresti vedere un numero di versione nel terminale.

---

## Passo 2: Esegui il Tuo Primo Modello — Il Comando Magico

Questo è il momento. Apri un terminale e digita:

```bash
ollama run llama3
```

Tutto qui. Ollama scaricherà il modello **Llama 3 8B** (~4,7 GB) al primo avvio, poi ti porterà in una sessione di chat interattiva direttamente nel terminale:

```
>>> Chi sei?
Sono Llama, un modello linguistico di grandi dimensioni addestrato da Meta.
Come posso aiutarti oggi?

>>> Scrivi una funzione Python che controlla se un numero è primo.
def is_prime(n):
    if n < 2:
        return False
    for i in range(2, int(n**0.5) + 1):
        if n % i == 0:
            return False
    return True
```

### Prova DeepSeek-R1 per Compiti di Ragionamento

**DeepSeek-R1** eccelle in matematica, logica e problem solving passo-passo:

```bash
ollama run deepseek-r1
```

### Altri Modelli Popolari

| Modello | Comando | Ideale Per |
|---|---|---|
| Llama 3 8B | `ollama run llama3` | Chat generica, coding |
| DeepSeek-R1 8B | `ollama run deepseek-r1` | Matematica, logica, ragionamento |
| Mistral 7B | `ollama run mistral` | Veloce, tuttofare efficiente |
| Gemma 2 9B | `ollama run gemma2` | Modello aperto di Google |
| Qwen 2.5 7B | `ollama run qwen2.5` | Compiti multilingue |

Esegui `ollama list` per vedere i modelli scaricati e `ollama rm <modello>` per eliminarne uno e liberare spazio.

---

## Passo 3: Aggiungi un'Interfaccia Chat con Open WebUI (Opzionale)

Il terminale funziona, ma se vuoi un'interfaccia **tipo ChatGPT**, installa **Open WebUI**. Il metodo più veloce è Docker:

```bash
docker run -d -p 3000:8080 --add-host=host.docker.internal:host-gateway \
  -v open-webui:/app/backend/data --name open-webui \
  --restart always ghcr.io/open-webui/open-webui:main
```

Poi apri [http://localhost:3000](http://localhost:3000) nel browser. Avrai un'interfaccia chat familiare con cronologia conversazioni, cambio modello, upload file e altro — tutto collegato alla tua istanza Ollama locale.

> **Senza Docker?** Esistono altri frontend leggeri come [Chatbox](https://chatboxai.app) (app desktop) o [Ollama Web UI](https://github.com/ollama-webui/ollama-webui) che non richiedono Docker.

---

## AI Locale vs. AI Cloud: Il Confronto Completo

| Caratteristica | AI Locale (Ollama) | AI Cloud (ChatGPT, Claude) |
|---|---|---|
| **Privacy** | I tuoi dati non lasciano mai il PC | Dati inviati a server remoti |
| **Costo** | Completamente gratuito | 20$/mese per i livelli premium |
| **Internet Necessario** | No — funziona completamente offline | Sì — sempre |
| **Velocità** | Dipende dal tuo hardware | Veloce (GPU lato server) |
| **Qualità Modello** | Eccellente (Llama 3, DeepSeek) | Eccellente (GPT-4o, Claude) |
| **Sforzo Setup** | Un comando | Creare un account |
| **Personalizzazione** | Controllo totale, fine-tuning | Limitata |
| **Conservazione Dati** | Controlli tutto tu | Si applicano le policy del provider |

**In sintesi:** I modelli cloud hanno ancora un vantaggio in capacità grezza per i compiti più complessi, ma per l'aiuto quotidiano con codice, scrittura, brainstorming e Q&A, i modelli locali sono **più che sufficienti** — e sono gratuiti e privati.

---

## Conclusione

Eseguire un'AI locale non è più un hobby di nicchia per ricercatori con GPU costose. Grazie a **Ollama** e all'ecosistema di modelli open-source, chiunque con un laptop moderno può avere un assistente AI privato, gratuito e funzionante offline in meno di 10 minuti.

I comandi da ricordare:

```bash
# Installa (Linux)
curl -fsSL https://ollama.com/install.sh | sh

# Esegui un modello
ollama run llama3

# Elenca i tuoi modelli
ollama list
```

Provalo. Una volta sperimentata la velocità e la privacy di un LLM locale, potresti trovarti a usare il cloud sempre meno.

> Hai bisogno di restare concentrato mentre programmi con la tua AI locale? Prova il nostro [mixer di suoni ambientali ZenFocus e timer Pomodoro](/it/tools/zen-focus/) — un altro strumento che funziona interamente nel browser senza alcun tracciamento.
