---
title: "Quiz phishing: sai riconoscere una truffa?"
description: "Test di phishing gratuito: 10 email, SMS, pagine di accesso, codici QR e link realistici. Riconosci la truffa, vedi i segnali d'allarme, condividi il punteggio."
intro: "Dieci scenari realistici — **email, SMS, pagine di accesso, codici QR e link** — estratti a caso da un insieme di 32. Per ognuno decidi: **phishing o legittimo?** Dopo ogni risposta i segnali d'allarme vengono evidenziati direttamente sulla simulazione, con una spiegazione di una riga. Tutti i marchi e i domini sono inventati e nulla di ciò che fai lascia il tuo browser."
date: 2026-10-26
lastmod: 2026-10-26
reviewed: false
keywords: ["quiz phishing", "test phishing", "riconoscere il phishing", "simulazione phishing", "come riconoscere una email truffa", "quiz smishing", "formazione sicurezza informatica", "test truffe online"]
tags: ["sicurezza", "phishing", "consapevolezza", "tool"]
app_category: "EducationalApplication"
tool_file: "/tools/phishing-quiz/"
tool_title: "Quiz sul phishing"
tool_height: 980
tool_sandbox: "allow-scripts allow-same-origin allow-top-navigation-by-user-activation"
tool_allow: "clipboard-write; web-share"
share_scores: 10
share_card_title: "Ho fatto {score}/10 al quiz sul phishing"
howto:
  - "Premi **Inizia il quiz**. Ricevi 10 scenari; tre o quattro sono legittimi, quindi \"è tutto phishing\" non funziona."
  - "Leggi la riga di contesto, poi esamina la simulazione come faresti con quella vera: l'indirizzo del mittente, dove porta davvero il link (passa sopra o metti il focus sul pulsante), la barra degli indirizzi, il nome dell'allegato."
  - "Rispondi **Phishing** o **Legittimo**. I segnali d'allarme (o gli indizi di un messaggio autentico) vengono numerati sulla simulazione e spiegati sotto."
  - "Alla fine ottieni un punteggio, un livello e gli argomenti da ripassare, con link a strumenti utili per ciascuno."
  - "Usa **Condividi il punteggio** per inviare il risultato: il testo condiviso contiene solo il punteggio e un link."
faq:
  - q: "Le aziende del quiz sono reali?"
    a: "No. Tutti i marchi, le persone, i numeri di telefono e i domini sono inventati, e tutti gli indirizzi web usano domini riservati alla documentazione (.example, .test) o l'intervallo IP di documentazione 192.0.2.x: niente nel quiz rimanda a un'organizzazione reale."
  - q: "Il mio punteggio o i miei clic vengono inviati da qualche parte?"
    a: "No. Il quiz funziona interamente nel browser e non fa richieste di rete. Non viene salvato nulla. Condividere è una tua scelta: il pulsante passa solo il punteggio e l'indirizzo del quiz al menu di condivisione del telefono, oppure li copia."
  - q: "Come vengono scelte le domande?"
    a: "Ogni partita estrae a caso 10 scenari su 32, con tre o quattro legittimi e almeno tre tipi diversi (email, SMS, pagina di accesso, codice QR, link). Rigiocando ottieni un mix diverso."
  - q: "Cosa sono lo smishing e il quishing?"
    a: "Lo smishing è il phishing via SMS o chat. Il quishing è il phishing tramite codice QR: su un adesivo, un manifesto o dentro un'email. Un codice QR nasconde l'indirizzo finché non lo inquadri e ti sposta sul telefono, dove non puoi passare sopra un link prima di aprirlo."
  - q: "Cosa faccio con un vero messaggio di phishing?"
    a: "Non cliccare, non rispondere e non aprire allegati. Segnalalo — al lavoro al reparto IT o sicurezza, altrimenti con l'opzione \"Segnala phishing\" del tuo provider di posta — poi cancellalo. Se hai già inserito una password, cambiala subito sul sito vero e attiva l'autenticazione a due fattori."
  - q: "Posso usarlo per la formazione sulla sicurezza?"
    a: "Sì, è gratuito e non richiede registrazione. Vedi \"Usalo per la formazione del team\" qui sotto per un modo semplice di proporlo in riunione."
---

## Come funziona

Ogni scenario è una simulazione costruita con veri elementi di pagina, non un'immagine: si può leggere con uno screen reader e giocare solo da tastiera. È accompagnata da una riga di contesto ("Aspetti una consegna…"), perché spesso la sospettosità di un messaggio dipende da cosa stavi facendo.

Gli scenari coprono gli schemi dietro la maggior parte del phishing:

- **Mittente e domini sosia** — `velorabank-alerts.test` al posto di `velorabank.example`, la cifra 1 al posto della l.
- **Dove porta davvero un link** — il testo visibile dice una cosa, la destinazione un'altra; un nome familiare solo come sottodominio del dominio di qualcun altro; il trucco della `@`.
- **Pressione** — scadenze, minacce di sospensione, segretezza, "ora non posso parlare".
- **Richieste che nessun servizio vero fa** — PIN della carta, gift card, contributi per sbloccare un pacco.
- **Allegati e codici QR** — tipi di file camuffati, codici QR che ti spostano sul telefono.

Nell'insieme ci sono anche messaggi legittimi, perché essere troppo sospettosi ha un costo: veri avvisi di sicurezza, ricevute e reimpostazioni di password che hai chiesto tu. Dopo la risposta, gli elementi che decidono il caso vengono numerati sulla simulazione.

La pagina del risultato ti assegna un livello ed elenca gli argomenti dietro i tuoi errori, con link a strumenti utili: [Link Hazmat](../link-hazmat/) per controllare i link sospetti e l'analizzatore di header email per verificare il mittente.

## Usalo per la formazione del team

Il quiz funziona bene come momento di 15 minuti in una riunione di team:

1. **Condividi lo schermo** e apri questa pagina. Avvia il quiz.
2. **Leggi ogni scenario ad alta voce** e lascia 30 secondi alla sala. Fai votare, per alzata di mano o in chat, prima che qualcuno clicchi.
3. **Rispondi come la maggioranza**, poi guardate insieme i segnali d'allarme numerati. Chiedi chi li aveva notati.
4. **Dopo la partita**, chiedi a tutti di giocare una volta da soli e condividere il punteggio in chat. Il messaggio condiviso contiene solo il punteggio e il link.
5. **Chiudi con la vostra procedura di segnalazione**: a chi scrivere, come, e cosa succede dopo una segnalazione.

Ogni partita è diversa, quindi le stesse persone possono rigiocare in una sessione successiva. Non viene tracciato nulla: il quiz è un esercizio per imparare, non una valutazione delle persone.

## Casi d'uso

- **Sensibilizzazione alla sicurezza** per team, scuole e famiglie, senza account né raccolta di dati.
- **Onboarding**: un'introduzione rapida e pratica ai messaggi che riceveranno i nuovi colleghi.
- **Autoverifica** prima di aprire quel messaggio della banca o del corriere che non ti aspettavi.
- **Didattica** sulla differenza tra un messaggio sospetto e uno autentico, usando le simulazioni come spunto di discussione.
