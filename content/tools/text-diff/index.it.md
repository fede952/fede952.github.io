---
title: "Confronto testi online: trova le differenze"
description: "Confronta due testi o file affiancati o in linea, evidenzia parole o caratteri, ignora spazi o maiuscole e copia un diff unificato. Privato, nel browser."
intro: "Incolla due versioni di un testo, di un file di configurazione o di codice per vedere ogni riga **aggiunta**, **rimossa** e **modificata**, in vista **affiancata** o **in linea**, con le **parole** o i **caratteri** cambiati evidenziati. Ignora spazi o maiuscole, comprimi le righe invariate e **copia un diff unificato** da applicare con `git apply` o `patch`. Nulla esce dal browser."
date: 2026-10-25
lastmod: 2026-10-25
reviewed: false
keywords: ["confronto testi", "confrontare due testi", "diff online", "trova differenze testo", "confrontare file", "diff unificato", "text compare", "comparare testi online"]
tags: ["strumenti-sviluppatori", "diff", "testo", "tool"]
app_category: "DeveloperApplication"
tool_file: "/tools/text-diff/"
tool_title: "Confronto testi (diff)"
tool_height: 900
tool_sandbox: "allow-scripts allow-same-origin allow-downloads"
tool_allow: "clipboard-write"
howto:
  - "Incolla la versione vecchia in **Originale** e quella nuova in **Modificato**, oppure carica ciascuna con **Apri file**. Premi **Esempio** per provarlo con due versioni di una configurazione nginx."
  - "Il risultato si aggiorna mentre scrivi. Scegli **Affiancata** per vedere le due versioni in colonna o **In linea** per un'unica colonna con righe − e + (predefinita sui telefoni)."
  - "Imposta **Evidenzia** su **Parole** o **Caratteri** per scegliere con quanta precisione segnare le modifiche dentro una riga cambiata."
  - "Spunta **Ignora spazi** per considerare uguali rientri e spazi multipli, e **Ignora maiuscole** per non distinguere maiuscole e minuscole."
  - "I tratti lunghi senza modifiche vengono compressi a tre righe di contesto; clicca una barra *⋯ righe invariate* per espanderla. Usa **Copia diff unificato** o **Scarica .diff** per condividere la modifica come patch."
faq:
  - q: "I miei testi vengono caricati da qualche parte?"
    a: "No. Il confronto avviene interamente nel browser con la libreria open source jsdiff, servita da questo sito. Nulla di ciò che incolli o apri viene inviato a un server, quindi puoi confrontare contratti, file di configurazione con segreti o codice privato."
  - q: "Che differenza c'è tra evidenziare parole e caratteri?"
    a: "In entrambi i casi i testi vengono prima abbinati riga per riga. Dentro ogni riga cambiata, la modalità parole segna intere parole e segni di punteggiatura diversi: la scelta più chiara per testi e quasi tutto il codice. La modalità caratteri segna i singoli caratteri e mostra un refuso di una lettera o una cifra cambiata in un identificatore o numero lungo."
  - q: "Cosa ignora esattamente \"Ignora spazi\"?"
    a: "Gli spazi a inizio e fine riga e la quantità di spazi tra le parole: `a  =  1` e `a = 1` contano come la stessa riga e i blocchi re-indentati non risultano modificati. Uno spazio tra due parole che prima erano unite resta una differenza. Le righe vuote vengono comunque confrontate come righe."
  - q: "Cos'è un diff unificato e come si applica?"
    a: "È il formato testuale standard di una modifica, usato da git, dagli strumenti di code review e da patch: intestazioni `---` e `+++`, poi blocchi che iniziano con `@@` con le righe rimosse precedute da − e quelle aggiunte da +, più tre righe di contesto. Salvalo come file `.diff` ed esegui `git apply modifica.diff` oppure `patch -p0 < modifica.diff`."
  - q: "Come decide che una riga è stata modificata e non rimossa e aggiunta?"
    a: "Usa l'algoritmo di diff di Myers sulle righe intere per trovare il minimo insieme di rimozioni e aggiunte. Quando un blocco di righe rimosse è seguito subito da righe aggiunte, vengono abbinate una a una come righe modificate. Se una coppia ha in comune meno del 30% circa del contenuto, viene mostrata come sostituita, senza evidenziazioni interne."
  - q: "Può confrontare file grandi?"
    a: "Sì, fino a diversi megabyte. I testi oltre circa 400.000 caratteri vengono confrontati quando premi Confronta invece che a ogni tasto. La vista mostra fino a 4.000 righe; il diff unificato contiene sempre il risultato completo. Testi molto diversi che richiederebbero troppo tempo vengono segnalati invece di bloccare la pagina."
  - q: "Gestisce i fine riga di Windows?"
    a: "Sì. I fine riga CRLF e CR vengono normalizzati prima del confronto, quindi lo stesso file salvato su Windows e su Linux risulta identico. L'assenza dell'a capo dopo l'ultima riga viene ignorata nella vista e segnalata nel diff unificato."
---

## Come funziona

### Prima le righe, poi parole o caratteri

I due testi vengono divisi in righe e confrontati con l'**algoritmo di diff di Myers** (quello di `git diff`), che trova la sequenza più breve di rimozioni e aggiunte per trasformare l'originale nel testo modificato. Le righe rimosse seguite subito da righe aggiunte vengono abbinate come *modificate* e ogni coppia viene confrontata di nuovo, token per token: parole, spazi e singoli segni di punteggiatura, oppure singoli caratteri. Vengono evidenziati solo i token diversi.

### Opzioni che non riscrivono il testo

**Ignora spazi** e **Ignora maiuscole** cambiano il modo in cui righe e token vengono *confrontati*, non ciò che viene mostrato: ogni colonna visualizza esattamente quello che hai incollato. Così la vista resta fedele quando, per esempio, un blocco di codice è stato re-indentato: le righe coincidono e nella colonna di destra vedi comunque il nuovo rientro.

### Diff unificato

I pulsanti **Copia diff unificato** e **Scarica .diff** creano una patch standard con tre righe di contesto, intestata con i nomi dei file se li hai aperti (altrimenti `original.txt` e `changed.txt`). Applicandola all'originale si ottiene esattamente il testo modificato; i test di questo strumento lo verificano con `git apply`.

## Casi d'uso

- **Codice e configurazioni.** Guarda cosa è cambiato tra due versioni di un file nginx, Docker Compose o YAML prima del deploy, senza fare commit.
- **Documenti e contratti.** Trova ogni parola modificata tra due bozze di un contratto, di un regolamento o di un articolo.
- **Log ed esportazioni.** Confronta due output di comandi, esportazioni CSV o elenchi per individuare le righe comparse o sparite.
- **Condividere una modifica.** Trasforma la tua modifica in un file `.diff` che un collega può applicare con git o incollare in un ticket.
- **Verifiche di copia-incolla.** Controlla che uno script, una chiave o uno snippet copiato tra sistemi sia arrivato senza modifiche invisibili: passa alla modalità caratteri per il massimo dettaglio.
