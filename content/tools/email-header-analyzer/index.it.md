---
title: "Analizzare gli header email: SPF e mittente"
description: "Incolla gli header di un'email per ricostruire il percorso, controllare SPF, DKIM e DMARC e scoprire i mittenti falsi. Gratis, privato, nel browser."
intro: "Incolla gli **header grezzi** di un'email sospetta per vedere da dove arriva davvero. L'analizzatore ricostruisce il **percorso server per server** con il ritardo di ogni passaggio, legge gli esiti **SPF, DKIM, DMARC e ARC** registrati dal tuo provider e segnala le **incongruenze** tra From, Reply-To e Return-Path. Tutto viene analizzato nel browser: gli header non vengono inviati da nessuna parte."
date: 2026-10-26
lastmod: 2026-10-26
reviewed: false
keywords: ["analizzare header email", "leggere intestazioni email", "controllare mittente email", "verificare se un'email è falsa", "header email gmail mostra originale", "controllo spf dkim dmarc email", "email spoofing come riconoscerlo", "tracciare email mittente"]
tags: ["security", "email", "phishing", "tool"]
app_category: "SecurityApplication"
tool_file: "/tools/email-header-analyzer/"
tool_title: "Analizzatore di header email"
tool_height: 1100
tool_sandbox: "allow-scripts allow-same-origin"
howto:
  - "Copia gli header grezzi dal tuo programma di posta (vedi **Come ottenere gli header** qui sotto) — oppure tutto il sorgente del messaggio: il corpo viene ignorato."
  - "Incollali nel riquadro. L'analisi parte da sola; premi **Analizza** per ripeterla."
  - "Leggi il **giudizio** e i **segnali**, dal più grave. Ognuno spiega cosa significa e quando è innocuo."
  - "Controlla la tabella **Identità del mittente**: i domini di From, Reply-To e Return-Path di solito appartengono alla stessa organizzazione."
  - "Segui il **percorso** dal primo server alla tua casella. Ritardi lunghi e server inattesi meritano un secondo sguardo."
faq:
  - q: "I miei header vengono caricati da qualche parte?"
    a: "No. Gli header vengono analizzati dal JavaScript di questa pagina e lo strumento non fa richieste di rete. Puoi aprire la pagina, staccarti da internet e funziona lo stesso."
  - q: "L'analizzatore può dirmi con certezza se un'email è phishing?"
    a: "Nessuno strumento può. Gli header mostrano come ha viaggiato il messaggio e se il dominio del mittente lo ha garantito. Un messaggio può superare tutti i controlli ed essere comunque una truffa inviata da un dominio somigliante di proprietà del truffatore: guarda anche il dominio del From e i link (li controlla lo strumento Link Hazmat di questo sito)."
  - q: "Perché alcuni header non vengono considerati affidabili?"
    a: "Tutto ciò che sta sotto le righe Received aggiunte dal tuo provider può essere scritto da chiunque lungo il percorso, mittente compreso. L'analizzatore si fida dell'header Authentication-Results del tuo provider e tratta il resto come dichiarazioni. Se incolli un messaggio inoltrato come allegato, analizza l'originale allegato, non il messaggio di inoltro."
  - q: "Cosa significano SPF, DKIM e DMARC?"
    a: "SPF elenca quali server possono inviare posta per un dominio. DKIM è una firma crittografica aggiunta dal dominio mittente. DMARC passa quando SPF o DKIM passano per lo stesso dominio mostrato nel From, e dice ai destinatari cosa fare quando nessuno dei due passa. ARC registra gli esiti originali quando una lista o un inoltro modificano il messaggio."
  - q: "Perché una newsletter autentica ha un Return-Path diverso?"
    a: "I servizi di invio spediscono per conto delle aziende e raccolgono i messaggi di errore su un loro dominio o un sottodominio. Per questo un Return-Path o un Message-ID su un altro dominio è segnalato solo come lieve: conta quando arriva insieme a un DMARC fallito o a un Reply-To su un dominio estraneo."
  - q: "Perché alcuni orari tornano indietro?"
    a: "Ogni server scrive l'ora del proprio orologio, e alcuni orologi sono sbagliati. L'analizzatore lo segnala come sfasamento dell'orologio e mostra comunque il percorso in ordine."
---

## Come ottenere gli header

La maggior parte dei programmi di posta nasconde gli header. Apri prima il messaggio, poi:

- **Gmail (web)** — apri il messaggio, fai clic sul pulsante **⋮ Altro** accanto a Rispondi e scegli **Mostra originale**. Premi **Copia negli appunti**. L'app Gmail per telefono non mostra gli header: usa un browser.
- **Outlook per Windows (classico)** — fai doppio clic sul messaggio per aprirlo nella sua finestra, poi **File → Proprietà**. Gli header sono nel riquadro **Intestazioni Internet** in basso: fai clic al suo interno, premi Ctrl+A e Ctrl+C.
- **Nuovo Outlook e Outlook sul web** — apri il messaggio, fai clic su **… Altre azioni → Visualizza → Visualizza dettagli messaggio** e copia il testo.
- **Apple Mail (Mac)** — seleziona il messaggio e scegli **Vista → Messaggio → Tutte le intestazioni** (⇧⌘H), oppure **Vista → Messaggio → Sorgente originale** (⌥⌘U) per il messaggio intero. Mail su iPhone e iPad non mostra gli header.
- **Thunderbird** — seleziona il messaggio e scegli **Visualizza → Sorgente messaggio** (Ctrl+U, ⌘U su Mac). Copia tutto ciò che sta sopra la prima riga vuota, o semplicemente tutto.

I nomi dei menu possono cambiare leggermente da una versione all'altra. Non inoltrare a te stesso l'email sospetta per vederne gli header: l'inoltro crea un nuovo messaggio con header nuovi.

## Come funziona

### Il percorso: le righe Received si leggono dal basso

Ogni server che gestisce un messaggio aggiunge in cima una riga **Received**, quindi la più vecchia è in fondo. L'analizzatore le capovolge in una cronologia dal primo server alla tua casella e mostra il tempo trascorso tra un passaggio e l'altro. Sono affidabili solo le righe aggiunte dal tuo provider: un mittente può scrivere righe Received false sotto di esse, ed è per questo che l'analizzatore si basa sugli esiti di autenticazione e non sull'origine dichiarata.

### Autenticazione: cosa ha già controllato il tuo provider

Quando un messaggio arriva, il tuo provider controlla **SPF**, **DKIM** e **DMARC** e registra gli esiti nell'header **Authentication-Results**. L'analizzatore legge quell'header e controlla anche l'**allineamento**: una firma DKIM o un SPF superato ti proteggono solo se riguardano la stessa organizzazione dell'indirizzo From. Non interroga il DNS e non verifica le firme da sé, perché il provider l'ha già fatto alla consegna, con le chiavi valide in quel momento.

### Incongruenze di identità

Il nome visualizzato è testo libero, quindi i truffatori ci mettono spesso un indirizzo affidabile (`"help@latuabanca.example" <x@random.test>`). L'analizzatore confronta i domini di **From**, **Reply-To**, **Return-Path** e del **Message-ID**, e spiega quali differenze sono normali per i servizi di invio e quali indicano un impostore.

## Casi d'uso

- **Un'email sospetta** — verifica se il messaggio della "banca" o del "corriere" arriva davvero da quel dominio prima di cliccare qualsiasi cosa.
- **Help desk e team di sicurezza** — smista rapidamente le segnalazioni di phishing e incolla la cronologia in un ticket.
- **Consegnabilità delle email** — scopri perché le tue newsletter falliscono DMARC o finiscono nello spam, e quale passaggio rallenta la consegna.
- **Per imparare** — capisci SPF, DKIM e DMARC con esempi realistici, poi mettiti alla prova con il [quiz sul phishing](../phishing-quiz/).
