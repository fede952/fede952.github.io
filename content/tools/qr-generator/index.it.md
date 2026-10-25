---
title: "Generatore QR Code Gratis (PNG)"
description: "Crea QR code per link o testo, scegli colori e correzione d'errore e scarica un PNG pronto per la stampa. Codici statici che non scadono mai."
intro: "Scrivi un link o un testo qualsiasi e ottieni un **QR code statico** da scaricare come PNG nitido e pronto per la stampa. Il codice viene creato nel tuo browser, contiene direttamente i tuoi dati e non scade mai. Le modalità **Wi-Fi** e **Contatto** creano codici che con una sola scansione collegano a una rete o salvano un biglietto da visita."
date: 2026-02-03
lastmod: 2026-10-25
reviewed: false
keywords: ["generatore qr code", "creare qr code gratis", "qr code gratis", "qr code per link", "qr code png", "qr code senza registrazione", "qr code statico", "qr code che non scade"]
tags: ["qr-code", "utility", "strumento"]
app_category: "UtilitiesApplication"
tool_file: "/tools/qr-generator/"
tool_title: "QuickLinker, generatore di QR code"
tool_height: 900
tool_sandbox: "allow-scripts allow-same-origin allow-downloads"
howto:
  - "Incolla un URL (compreso `https://`) o scrivi un testo qualsiasi nella casella. Funzionano anche lettere accentate, emoji e alfabeti non latini."
  - "Per una rete apri **Wi-Fi** e inserisci nome, password e sicurezza; per un biglietto da visita apri **Contatto** e compila i campi che ti servono. Il testo esatto che verrà codificato compare in **Testo codificato**."
  - "Se vuoi, scegli un colore di **Primo Piano** e di **Sfondo**. Tieni il primo piano ben più scuro dello sfondo, altrimenti molte fotocamere dei telefoni non lo leggono."
  - "Scegli il livello di **Correzione Errore**: **M (15%)** è quello predefinito; usa **Q** o **H** se il codice sarà stampato piccolo, all'aperto o con un logo sopra."
  - "Premi **Genera QR** e controlla l'anteprima inquadrando lo schermo con la fotocamera del telefono."
  - "Premi **Scarica .PNG** per salvare un'immagine di circa 1200 px con il margine bianco richiesto, pronta per la stampa o le slide."
faq:
  - q: "Questi QR code scadono?"
    a: "No. Sono QR code statici: il link o il testo è codificato direttamente nel disegno. Non puntano a nessun nostro server, quindi non c'è nulla da disattivare, nessun abbonamento e nessun limite di scansioni. Il rovescio della medaglia è che non puoi cambiare la destinazione in seguito: se l'URL cambia, genera un nuovo codice."
  - q: "Questo generatore di QR code è davvero gratuito?"
    a: "Sì, senza account, senza filigrana e senza limiti al numero di codici. La pagina si finanzia con gli annunci mostrati attorno allo strumento, non bloccando funzioni."
  - q: "Che differenza c'è tra un QR code statico e uno dinamico?"
    a: "Un QR code dinamico contiene un link breve verso il server del fornitore, che poi reindirizza al tuo URL reale. Così il fornitore può contare le scansioni e cambiare la destinazione, ma il codice smette di funzionare se smetti di pagare o se il servizio chiude, e ogni scansione passa dai suoi server. Un codice statico, come quelli creati qui, porta direttamente al tuo URL."
  - q: "Quale livello di correzione d'errore scegliere?"
    a: "L recupera circa il 7% dei moduli danneggiati, M il 15%, Q il 25% e H il 30%. I livelli più alti rendono il codice più fitto a parità di contenuto. M va bene per schermi e stampe pulite; scegli Q o H per adesivi piccoli, superfici ruvide o se vuoi mettere un logo al centro."
  - q: "Quanto testo entra in un QR code?"
    a: "Il generatore sceglie automaticamente la più piccola delle 40 versioni QR che basta per il contenuto. Al livello M un codice versione 40 contiene circa 2.300 byte di testo, ma codici così grandi sono difficili da leggere col telefono. Per i link, più corto è meglio: un URL di 30–60 caratteri dà un codice pulito e facile da scansionare."
  - q: "Perché il mio QR code colorato non si legge?"
    a: "I lettori cercano moduli scuri su sfondo chiaro con un contrasto sufficiente. Colori invertiti (chiaro su scuro), coppie poco contrastate come giallo su bianco o un'immagine dietro il codice sono le cause più comuni. Nero o un colore scuro su bianco è la scelta più sicura."
  - q: "I dati che scrivo vengono inviati da qualche parte?"
    a: "No. Il QR code viene calcolato da una libreria JavaScript che gira in questa pagina e disegnato su un canvas. Non viene caricato nulla, il che conta se stai codificando una password del Wi-Fi, un URL interno o una nota privata."
  - q: "Come funziona un QR code per il Wi-Fi?"
    a: "Contiene un breve testo nel formato `WIFI:` che le fotocamere di Android e iPhone riconoscono, per esempio `WIFI:T:WPA;S:Casa;P:segreta;;`. Inquadrandolo, il telefono propone di collegarsi senza digitare la password. I caratteri speciali nel nome o nella password (`\\ ; , : \"`) vengono preceduti da una barra rovesciata, come richiede il formato, quindi anche una password come `p;ss:word` funziona. La password è leggibile da chiunque scansioni il codice: stampalo solo dove gli ospiti sono i benvenuti."
  - q: "Che formato si usa per i contatti e cosa può contenere?"
    a: "Una vCard 3.0, la versione che le fotocamere dei telefoni importano in modo più affidabile: nome, organizzazione, ruolo, cellulare, email, sito web, indirizzo e una nota. I campi vuoti vengono omessi per tenere il codice piccolo. Virgole, punti e virgola e a capo vengono codificati come vuole lo standard vCard. Un biglietto completo produce un codice fitto: tralascia ciò che non serve e tieni la correzione d'errore su L o M."
---

## Come funziona

Lo strumento usa la libreria open source **qrcode-generator** di Kazuhiko Arase (v1.4.4, ospitata su questo sito) e disegna il risultato su un canvas HTML.

1. **Codifica.** Il testo viene convertito in byte **UTF-8** e memorizzato in *byte mode*, così `é`, `ß`, `ç`, `€` e le emoji risultano esattamente come li hai scritti quando un telefono li legge. (La libreria di default terrebbe un solo byte per carattere rovinando tutto ciò che esce dal latino di base, quindi la pagina la imposta esplicitamente su UTF-8.)
2. **Scelta della versione.** La libreria sceglie la **versione QR** più piccola, dalla 1 (21 × 21 moduli) alla 40 (177 × 177), che può contenere i tuoi dati al livello di correzione scelto.
3. **Correzione d'errore.** I QR code aggiungono codeword di correzione **Reed–Solomon**, così un lettore può ricostruire parti mancanti o sporche: il livello **L** recupera circa il 7%, **M** il 15%, **Q** il 25% e **H** il 30% dei codeword.
4. **Disegno.** Ogni modulo scuro viene disegnato come un quadrato del colore di primo piano. Attorno al simbolo lo strumento lascia una **zona di rispetto di 4 moduli** del colore di sfondo, il margine richiesto dallo standard QR (ISO/IEC 18004): senza, i lettori vanno in difficoltà appena il codice è su una pagina colorata.
5. **Esportazione.** L'anteprima a schermo è larga circa 300 px. Al download il codice viene ridisegnato a circa **1200 px**, con ogni modulo di un numero intero di pixel perché i bordi restino netti, e salvato come `qrcode.png`.

| Contenuto | Lunghezza tipica | Versione al livello M | Moduli |
|---|---|---|---|
| URL breve | 25 caratteri | 2 | 25 × 25 |
| URL normale con percorso | 60 caratteri | 4 | 33 × 33 |
| URL lungo con parametri di tracciamento | 150 caratteri | 8 | 49 × 49 |
| Un paragrafo di testo | 500 caratteri | 17 | 85 × 85 |

Meno moduli ci sono, più è grande ciascuno una volta stampato e più facile è leggere il codice da lontano: per questo togliere i parametri di tracciamento da un URL spesso conta più del livello di correzione.

### Codici Wi-Fi e contatto

In modalità **Wi-Fi** lo strumento scrive `WIFI:T:<WPA|WEP|nopass>;S:<rete>;P:<password>;H:true;;` (il campo `H` solo per le reti nascoste); `WPA` copre WPA, WPA2 e WPA3 Personal, perché la versione esatta la negozia il telefono. In modalità **Contatto** scrive una vCard 3.0 con fine riga CRLF. Entrambi i formati sono verificati decodificando il PNG scaricato e confrontando il risultato carattere per carattere, anche con nomi e password pieni di `; , : " \`.

## Casi d'uso

- **Stampa e packaging.** Metti un QR code su volantini, biglietti da visita, menu o etichette che apra il tuo sito, una pagina di recensioni o un manuale. Un codice statico funziona finché funziona l'URL.
- **Presentazioni e poster.** Fai aprire al pubblico le slide, un sondaggio o un repository senza dover digitare un indirizzo lungo.
- **Condividere testo offline.** Codifica una breve nota, un numero di serie o dei contatti che un telefono può leggere senza rete.
- **Testare le tue app.** Genera codici per deep link, URL di staging o test di callback OAuth senza incollare indirizzi interni in un servizio di terzi.
- **Formazione sulla sicurezza.** Il "quishing" (phishing via QR) nasconde link malevoli dietro i codici. Generarne di tuoi ti permette di mostrare ai colleghi quanto sia facile far puntare un codice ovunque, e perché l'anteprima dell'URL sul telefono va guardata prima di toccare.
