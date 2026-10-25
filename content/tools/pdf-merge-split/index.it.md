---
title: "Unire e dividere PDF online gratis"
description: "Unisci file PDF, dividili per pagine o intervalli, riordina, ruota ed elimina pagine nel browser. I tuoi PDF non vengono mai caricati. Gratis."
intro: "**Unisci PDF** in un unico file, **dividi un PDF** in singole pagine o intervalli e intanto riordina, ruota o elimina le pagine — con miniature che puoi trascinare. Tutto avviene in questa scheda del browser: contratti, buste paga e scansioni non lasciano mai il tuo dispositivo."
date: 2026-10-25
lastmod: 2026-10-25
reviewed: false
keywords: ["unire pdf", "dividere pdf", "unire file pdf", "riordinare pagine pdf", "dividere pdf online", "unire pdf senza caricare", "estrarre pagine da pdf", "ruotare pagine pdf"]
tags: ["pdf", "privacy", "documenti", "tool"]
app_category: "UtilitiesApplication"
tool_file: "/tools/pdf-merge-split/"
tool_title: "Unire, dividere e riordinare PDF"
tool_height: 760
tool_sandbox: "allow-scripts allow-same-origin allow-downloads"
howto:
  - "Trascina uno o più file PDF nel riquadro, oppure fai clic per sceglierli. Ogni pagina compare come miniatura numerata, nell'ordine dei file."
  - "Sistema le pagine: trascina una miniatura in una nuova posizione oppure usa i pulsanti **←** e **→** (comodi da telefono). **⟳** ruota una pagina di 90°, **✕** la esclude dal risultato."
  - "Per unire tutto, imposta il **Nome del file** e premi **Unisci e scarica**: ottieni un unico PDF con le pagine esattamente come le hai disposte."
  - "Per dividere, scegli **Ogni pagina in un PDF separato** oppure **Per intervalli di pagine** e scrivi gruppi come `1-3, 4, 5-` (i numeri sono quelli delle miniature; `5-` significa dalla pagina 5 alla fine)."
  - "Premi **Dividi e scarica (.zip)**. Ogni gruppo diventa un PDF con il nome del primo file (`report-part-1.pdf`…); con un solo gruppo ricevi direttamente il PDF."
faq:
  - q: "I miei PDF vengono caricati da qualche parte?"
    a: "No. I file vengono letti dal browser, visualizzati in anteprima con pdf.js e ricostruiti con pdf-lib, entrambi in esecuzione in questa scheda. La pagina scarica queste librerie una volta e non invia nulla; puoi controllare il pannello Rete mentre unisci i file."
  - q: "Unire i PDF riduce la qualità?"
    a: "No. Le pagine vengono copiate così come sono: il testo resta testo, le immagini mantengono la compressione originale e i font vengono riportati. Nulla viene rasterizzato o ricompresso, quindi il risultato è nitido quanto gli originali."
  - q: "Posso unire PDF protetti da password?"
    a: "Non direttamente: un PDF cifrato non si può leggere senza password, e lo strumento lo segnala invece di produrre un file rovinato. Aprilo in un lettore PDF, salva una copia senza password e aggiungi quella."
  - q: "Link, segnalibri e campi dei moduli vengono mantenuti?"
    a: "Il contenuto delle pagine, le annotazioni e i link sulle pagine vengono copiati. L'indice (segnalibri) e la logica dei moduli interattivi appartengono al file originale nel suo insieme e non vengono ricostruiti nel PDF unito: controlla i moduli dopo l'unione."
  - q: "Quanto possono essere grandi i file?"
    a: "Non c'è un limite fisso: dipende dalla memoria del dispositivo. Documenti di qualche centinaio di pagine funzionano bene su un computer. Le miniature vengono generate per ogni pagina, quindi i file molto grandi ci mettono di più a comparire."
  - q: "Cosa fa la rotazione al file?"
    a: "Imposta la rotazione della pagina nel PDF (a scatti di 90°), che tutti i lettori rispettano. Il contenuto non viene ridisegnato: la rotazione è senza perdita e si annulla ruotando di nuovo."
  - q: "Come estraggo solo alcune pagine?"
    a: "Usa **Per intervalli di pagine** con un solo gruppo, ad esempio `3-5`: scarichi un PDF che contiene solo le pagine 3, 4 e 5. In alternativa elimina con ✕ le pagine che non ti servono e unisci."
---

## Come funziona

### Due librerie, entrambe locali

Leggere un PDF e scriverne uno sono compiti diversi, quindi lo strumento usa due librerie open source, servite da questo sito e caricate solo quando aggiungi un file:

- **pdf.js** (Mozilla, Apache-2.0), il motore del visualizzatore PDF di Firefox, genera una piccola miniatura di ogni pagina in un worker in background, così la pagina resta reattiva.
- **pdf-lib** (MIT) costruisce il risultato. Per ogni pagina, nel tuo ordine, copia l'oggetto pagina dal documento di origine — flussi di contenuto, font, immagini e annotazioni — in un nuovo documento con `copyPages`, applica la rotazione scelta e salva.

Prima di tutto lo strumento controlla che ogni file inizi con `%PDF-`, così un documento Word rinominato o un download corrotto viene segnalato con il suo nome.

### Ordine delle pagine e intervalli

Le miniature sono un'unica lista per tutti i file: l'unione le scrive in quell'ordine e anche i numeri che scrivi per dividere si riferiscono a essa. Gli intervalli sono gruppi separati da virgole; ogni gruppo può essere una pagina singola (`4`), un intervallo (`1-3`), un intervallo aperto (`5-` fino all'ultima pagina) o un inizio aperto (`-3`). Ogni gruppo diventa un PDF; più PDF vengono raccolti in uno ZIP con JSZip.

### Cosa non viene incluso

Il nuovo documento riceve da pdf-lib metadati nuovi al posto dei titoli e degli autori di origine, e le funzioni a livello di documento, come l'indice dei segnalibri e gli script dei moduli, non vengono ricreate. Per unire e dividere ogni giorno — fatture, scansioni, capitoli, slide — è esattamente ciò che serve.

## Casi d'uso

- **Riunire le scansioni** di un contratto o di un modulo di più pagine in un unico file prima di inviarlo per email.
- **Dividere un PDF grande** — un libro di testo, un manuale, un anno di estratti conto — in capitoli o mesi.
- **Eliminare pagine** che contengono dati personali prima di condividere un documento.
- **Correggere ordine e orientamento** di un documento scansionato capovolto o in disordine.
- **Preparare una candidatura**: CV, lettera di presentazione e certificati nell'ordine richiesto, senza affidarli a un servizio online di cui non sai nulla.
