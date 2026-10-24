---
title: "Verifica Sicurezza Password e Generatore"
description: "Scopri quanto è sicura una password (entropia in bit, tempo per craccarla) e genera password o passphrase casuali. Funziona interamente nel browser."
intro: "**PassFort** genera password e passphrase casuali con il generatore crittografico del tuo browser e verifica entropia e tempo di attacco brute-force di qualsiasi password. Nulla di ciò che scrivi lascia questa pagina."
date: 2026-02-03
lastmod: 2026-10-24
reviewed: false
keywords: ["verifica sicurezza password", "generatore password sicure", "generatore passphrase", "calcolo entropia password", "quanto tempo per craccare una password", "password casuale", "test password", "password forte"]
tags: ["sicurezza", "password", "privacy", "strumento"]
app_category: "SecurityApplication"
tool_file: "/tools/pass-fort/"
tool_title: "PassFort: generatore e verifica sicurezza password"
tool_height: 900
tool_sandbox: "allow-scripts allow-same-origin"
tool_allow: "clipboard-write"
howto:
  - "Apri la scheda **Generator**. Scegli la lunghezza (da 8 a 128 caratteri) e i gruppi di caratteri: maiuscole, minuscole, cifre, simboli."
  - "Per qualcosa da digitare e ricordare, attiva **Passphrase Mode** e scegli da 3 a 8 parole. Per una master password usane almeno 6."
  - "Premi **Generate Password** finché il risultato ti piace, poi copialo con il pulsante degli appunti e incollalo direttamente nel tuo password manager."
  - "Per controllare una password che usi già, passa alla scheda **Auditor** e scrivila o incollala. Il pulsante con l'occhio la mostra o la nasconde."
  - "Leggi il misuratore di entropia, il tempo stimato per craccarla e la checklist: tutto ciò che è rosso va sistemato prima di riusare quella password."
faq:
  - q: "È sicuro inserire la mia vera password in questo verificatore?"
    a: "Sì. L'auditor è JavaScript che gira dentro questa pagina: non invia mai in rete ciò che scrivi, e il valore sparisce appena svuoti il campo o chiudi la scheda. Puoi verificarlo negli strumenti per sviluppatori del browser (scheda Rete) mentre digiti. Se preferisci, prova una password che *segue lo stesso schema* di quella vera."
  - q: "Quanti bit di entropia servono per una password sicura?"
    a: "Per account protetti da un hash lento e con salt, 60–70 bit di entropia *casuale* resistono a lungo a un attacco brute-force offline. Per la master password del password manager o per la cifratura del disco punta a 80–100 bit. Una password casuale di 16 caratteri con tutti e quattro i gruppi dà circa 103 bit; una passphrase PassFort di 7 parole circa 72 bit."
  - q: "Meglio una passphrase o una password casuale?"
    a: "Sono entrambe robuste se parole o caratteri sono scelti a caso da una macchina. Le password di caratteri casuali hanno più entropia per carattere e sono ideali quando è il password manager a digitarle. Le passphrase sono più facili da scrivere e ricordare, quindi sono la scelta migliore per le poche password che devi inserire a mano, purché usi abbastanza parole."
  - q: "Perché il verificatore dice \"secoli\" per una password che so essere debole?"
    a: "La stima presuppone che ogni carattere sia stato scelto a caso. Un attaccante reale parte da dizionari, liste di password trapelate e regole come \"maiuscola iniziale, anno alla fine\": così `Estate2024!` cade in pochi secondi anche se la sua entropia grezza sembra discreta. PassFort segnala solo alcuni schemi evidenti (inizio con 123, abc, password, qwerty, 111 o aaa), quindi per una password inventata da una persona considera il punteggio come un limite massimo."
  - q: "Cosa significa \"10 miliardi di tentativi al secondo\"?"
    a: "È la velocità d'attacco ipotizzata: più o meno una GPU moderna contro un hash veloce e senza salt come MD5 o NTLM. Contro bcrypt, scrypt o Argon2 un attaccante è migliaia di volte più lento, quindi i tempi reali sono di solito più lunghi. Contro un form di login online con limiti di tentativi lo sono molto di più."
  - q: "PassFort salva o registra le password che genera?"
    a: "No. Le password generate esistono solo nella memoria della pagina finché non le copi. Non ci sono account, archivi o server dietro lo strumento. Salva la password in un password manager: una volta chiusa la scheda non si può recuperare."
  - q: "Quanto deve essere lunga una password nel 2026?"
    a: "Se la genera e la conserva un password manager, usa almeno 16 caratteri casuali: non ti costa nulla. Se devi ricordarla, usa una passphrase di 6 o più parole casuali. La lunghezza batte le regole di complessità: una password lunga e casuale di sole minuscole è più forte di una corta piena di simboli."
---

## Come funziona

### Il generatore

Ogni carattere arriva da `crypto.getRandomValues()`, il generatore di numeri casuali crittograficamente sicuro della Web Crypto API, che il browser alimenta con la sorgente di entropia del sistema operativo. `Math.random()` non viene mai usato.

Per trasformare un numero casuale a 32 bit in una posizione nel set di caratteri, PassFort usa il **rejection sampling**: i valori che cadono nell'ultimo "blocco" incompleto dell'intervallo a 32 bit vengono scartati ed estratti di nuovo. Il più semplice `casuale % dimensione` renderebbe leggermente più probabili i primi caratteri del set. È uno scarto minimo, ma non c'è motivo di accettarlo.

I quattro gruppi sono 26 maiuscole, 26 minuscole, 10 cifre e 26 simboli (`!@#$%^&*()_+-=[]{}|;:,.<>?`), 88 caratteri in tutto. Ogni carattere aggiunge quindi log₂(88) ≈ **6,46 bit** di entropia:

| Lunghezza | Tutti e quattro i gruppi | Solo minuscole |
|---|---|---|
| 12 | ≈ 77 bit | ≈ 56 bit |
| 16 | ≈ 103 bit | ≈ 75 bit |
| 20 (predefinita) | ≈ 129 bit | ≈ 94 bit |

I caratteri sono estratti in modo indipendente, quindi una password corta non è *garantito* che contenga tutti i gruppi selezionati. Rigenerala se un sito pretende, ad esempio, almeno una cifra.

### La modalità passphrase

La modalità passphrase sceglie parole da un elenco interno di **1.207 parole inglesi** con lo stesso indice casuale senza distorsioni, mette la maiuscola a ciascuna e le unisce con trattini (per esempio `Harbor-Canyon-Crisp-Velvet`). Ogni parola aggiunge log₂(1207) ≈ **10,24 bit**: 4 parole danno circa 41 bit, 6 parole circa 61 bit e il massimo di 8 parole circa 82 bit.

È meno per parola rispetto a un elenco Diceware completo da 7.776 parole (12,9 bit), ed è per questo che su questa pagina consigliamo almeno 6 parole per tutto ciò che conta. Maiuscole e trattini sono fissi, quindi non aggiungono entropia.

### L'auditor

L'auditor stima la dimensione dell'"alfabeto" da cui attinge la tua password: 26 se contiene una minuscola, +26 per le maiuscole, +10 per le cifre e +33 per qualsiasi altro carattere. L'entropia è poi `lunghezza × log₂(alfabeto)`.

Il tempo per craccarla è quello necessario a provare tutte le 2^entropia combinazioni a **10¹⁰ tentativi al secondo**, mostrato in unità comprensibili fino a "secoli". Il misuratore si riempie a 100 bit e passa da rosso ad arancione, giallo e verde a 25, 50 e 75 bit. Sotto trovi otto controlli: almeno 8 e 12 caratteri, ciascun gruppo di caratteri, nessuno schema iniziale comune, almeno 60 bit.

È il classico modello "brute-force". È preciso per password casuali come quelle del generatore, ed è **ottimista per le password inventate dalle persone**, perché non riconosce parole di dizionario, nomi o date.

## Casi d'uso

- **Nuovi account.** Genera una password di 16–20 caratteri e salvala nel password manager. Non avrai mai più bisogno di vederla.
- **Le password da ricordare.** Master password del password manager, login del computer, cifratura del disco: usa una passphrase di 6–8 parole che riesci a digitare senza errori.
- **Controllare le vecchie abitudini.** Incolla una password che usi da anni, guarda il punteggio e cambia quelle deboli, partendo da email e banca.
- **Chiavi Wi-Fi e segreti condivisi.** Le passphrase WPA2/WPA3 arrivano a 63 caratteri: una lunga e casuale non costa nulla e blocca il cracking offline di un handshake catturato.
- **Formazione e policy aziendali.** La tabella qui sopra e il misuratore in tempo reale rendono concreta l'entropia quando spieghi ai colleghi perché "8 caratteri con un simbolo" non è più una buona regola.
