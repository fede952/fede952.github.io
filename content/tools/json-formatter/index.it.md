---
title: "Formattatore e validatore JSON, in YAML"
description: "Formatta, minimizza e valida JSON con errori a riga e colonna esatte, ordina le chiavi, esplora l'albero e converti JSON in YAML o CSV. Privato, nel browser."
intro: "Incolla del JSON per **formattarlo** con 2 o 4 spazi o tabulazioni, **minimizzarlo**, **validarlo** con *riga e colonna* esatte del primo errore, **ordinare le chiavi**, esplorarlo come **albero** comprimibile o convertire **JSON in YAML**, **YAML in JSON** e **JSON in CSV**. I file da diversi megabyte vengono gestiti da un worker in background; non viene caricato nulla."
date: 2026-10-25
lastmod: 2026-10-25
reviewed: false
keywords: ["formattatore json", "validatore json", "formattare json online", "json beautifier", "json in yaml", "yaml in json", "json in csv", "minimizzare json"]
tags: ["strumenti-sviluppatori", "json", "yaml", "tool"]
app_category: "DeveloperApplication"
tool_file: "/tools/json-formatter/"
tool_title: "Formattatore, validatore e convertitore JSON"
tool_height: 820
tool_sandbox: "allow-scripts allow-same-origin allow-downloads"
tool_allow: "clipboard-write"
howto:
  - "Incolla il JSON in **Input**, apri un file `.json` con **Apri file** oppure premi **Esempio** per provarlo."
  - "Premi **Formatta** (o Ctrl/⌘ + Invio) per indentarlo con il **Rientro** scelto; **Minimizza** toglie tutti gli spazi. Spunta **Ordina chiavi** per mettere in ordine alfabetico le chiavi di ogni oggetto."
  - "Se il JSON non è valido, la riga di stato indica il problema e la posizione — per esempio *Riga 3, colonna 14: virgola finale* — e mostra la riga incriminata con un segno sotto il carattere esatto."
  - "Converti con **In YAML** o **In CSV** (scegli il **Separatore CSV**). Per il percorso inverso passa a **Input YAML**, incolla lo YAML e premi **Formatta** per ottenere JSON."
  - "Passa l'output tra **Testo** e **Albero** per esplorare strutture grandi, poi **Copia** o **Scarica** il risultato."
faq:
  - q: "Il mio JSON viene inviato a un server?"
    a: "No. Analisi, formattazione e conversione avvengono nel browser — gli input oltre 2 MB in un Web Worker nella stessa scheda. La pagina non fa richieste con i tuoi dati: risposte API, token e file di configurazione restano sul tuo computer."
  - q: "Perché dice \"virgola finale\"?"
    a: "Il JSON non ammette una virgola dopo l'ultimo elemento di un oggetto o di un array, anche se JavaScript la accetta. `[1, 2,]` e `{\"a\": 1,}` non sono JSON valido: togli l'ultima virgola. Altri errori comuni che il validatore riconosce: apici singoli, chiavi senza virgolette, commenti e valori NaN o Infinity."
  - q: "Come trova riga e colonna di un errore?"
    a: "I messaggi di JSON.parse cambiano da browser a browser e alcuni danno solo una posizione in caratteri. Quando l'analisi fallisce, lo strumento rilegge il testo con un proprio scanner rigoroso secondo la RFC 8259, che si ferma al primo carattere impossibile in un JSON valido e ne riporta riga e colonna."
  - q: "Come viene convertito il JSON in CSV?"
    a: "Un array di oggetti diventa una riga per oggetto. Gli oggetti annidati diventano colonne con il punto (`address.city`), gli array dentro una riga vengono scritti come testo JSON e le colonne sono l'unione di tutte le chiavi nell'ordine in cui compaiono. I valori con virgole, virgolette o a capo vengono messi tra virgolette come vuole la RFC 4180. Un array di array viene scritto riga per riga."
  - q: "Commenti e ancore YAML vengono mantenuti nella conversione?"
    a: "Da YAML a JSON le ancore e gli alias vengono risolti in valori normali e i commenti si perdono, perché il JSON non li prevede. Da JSON a YAML si ottiene YAML a blocchi senza ancore, quindi le strutture ripetute vengono scritte per intero."
  - q: "Ordinare le chiavi modifica i miei dati?"
    a: "Nessun valore cambia. Le chiavi degli oggetti vengono riordinate per code point Unicode (le maiuscole prima delle minuscole) a ogni livello; gli array mantengono il loro ordine, perché l'ordine fa parte del dato. L'output ordinato è comodo per i diff e per file stabili sotto controllo di versione."
  - q: "Quanto può essere grande il file?"
    a: "Decine di megabyte su un computer. Oltre 2 MB, formattazione e minimizzazione girano in un worker in background, così la pagina resta reattiva. La vista ad albero crea i nodi solo quando li apri e mostra al massimo 500 figli per nodo alla volta."
---

## Come funziona

### Una validazione che si spiega

L'input viene analizzato con `JSON.parse` nativo del browser, il parser più veloce e fedele allo standard disponibile. Quando fallisce, un secondo scanner volutamente piccolo percorre il testo seguendo la grammatica della RFC 8259 — oggetti, array, stringhe con le loro regole di escape, numeri senza zeri iniziali, `true`, `false`, `null` — e si ferma al primo carattere che non può far parte di un documento valido. Quella posizione viene convertita in riga e colonna e associata a una spiegazione chiara: virgola finale, due punti mancanti, stringa tra apici singoli, tabulazione non escapata dentro una stringa o testo dopo la fine del documento.

### Formattare, minimizzare e ordinare

La formattazione usa `JSON.stringify` con il rientro scelto (2 spazi, 4 spazi o una tabulazione). La minimizzazione scrive la stessa struttura senza spazi. **Ordina chiavi** ricostruisce ogni oggetto con le chiavi in ordine di code point prima di serializzare; l'ordine degli array non cambia mai. I numeri vengono scritti come li legge JavaScript, quindi gli interi oltre 2^53 perdono precisione: conserva questi ID come stringhe.

### Input grandi

Oltre 2 MB in UTF-8, formattazione e minimizzazione passano a un **Web Worker**, un thread in background nella stessa scheda, così scrivere e scorrere restano fluidi mentre viene elaborato un grosso dump di API. La vista ad albero viene costruita su richiesta: i figli di un nodo vengono creati solo quando lo espandi.

### Conversioni

Il supporto YAML viene da **js-yaml** (MIT), servito da questo sito e caricato solo la prima volta che usi YAML. Lo YAML viene letto con lo schema sicuro predefinito, quindi non può creare oggetti personalizzati né eseguire codice. Il CSV è generato dallo strumento stesso, seguendo le regole di quoting e i fine riga della RFC 4180.

## Casi d'uso

- **Debug delle API.** Indenta una risposta su una sola riga, trova nell'albero il campo che ti serve o individua esattamente dove si rompe un payload modificato a mano.
- **Configurazioni.** Converti uno snippet Kubernetes o Docker Compose tra YAML e JSON, oppure valida un `package.json` o un `tsconfig.json` dopo una modifica.
- **Esportazione di dati.** Trasforma un array di record in CSV per un foglio di calcolo, con i campi annidati appiattiti in colonne.
- **Code review e versionamento.** Ordina le chiavi e formatta in modo coerente perché i diff mostrino modifiche reali e non riordini.
- **Dati sensibili.** Ispeziona payload JWT, corpi di webhook o log con dati personali senza incollarli su un sito di terze parti.
