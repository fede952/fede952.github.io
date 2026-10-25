---
title: "Generatore di password e passphrase"
description: "Genera password casuali robuste fino a 64 caratteri, o passphrase diceware da elenchi di parole in 6 lingue. Entropia esatta, non viene inviato nulla."
intro: "Un **generatore di password sicure** a un clic: scegli lunghezza e tipi di caratteri per una password casuale, oppure passa a **Passphrase** per una sequenza di parole casuali (in italiano, inglese, tedesco, spagnolo, francese o portoghese). Tutto viene estratto dal generatore crittografico del browser, con la robustezza esatta mostrata in bit."
date: 2026-02-03
lastmod: 2026-10-26
reviewed: false
keywords: ["generatore password sicure", "generatore password casuali", "creare password sicura", "password casuale online", "generatore password forte", "password 16 caratteri", "generare password"]
tags: ["sicurezza", "password", "strumento"]
app_category: "SecurityApplication"
tool_partial: "password-generator"
howto:
  - "Sposta il cursore **Lunghezza** (da 8 a 64 caratteri). A ogni spostamento viene generata subito una nuova password."
  - "Togli la spunta ai gruppi di caratteri che il sito non accetta: maiuscole **A–Z**, minuscole **a–z**, cifre **0–9** o simboli **!@#**."
  - "Guarda la riga sotto la password: indica l'entropia in bit e un giudizio (Debole, Buona, Forte)."
  - "Premi **Genera password** per averne una nuova, poi il pulsante di copia accanto al campo la mette negli appunti."
  - "Incollala nel tuo password manager *prima* di chiudere la pagina: il generatore non conserva alcuna cronologia."
  - "Per qualcosa da digitare o ricordare, scegli **Passphrase**: imposta il numero di parole, l'elenco (segue la lingua della pagina) e il separatore. Sei parole italiane danno 66 bit; sette, 77."
faq:
  - q: "Questo generatore di password è davvero casuale?"
    a: "Sì. Ogni carattere viene scelto con `crypto.getRandomValues()`, il generatore di numeri casuali crittograficamente sicuro del browser, con rejection sampling in modo che ogni carattere del set abbia esattamente la stessa probabilità. Non usa `Math.random()`, che è prevedibile e non adatto ai segreti."
  - q: "Il sito può vedere le password che genero?"
    a: "No. Il generatore è poche righe di JavaScript che girano nel tuo browser: nessuna richiesta a un server, nessun log, nessun salvataggio. Se ti scolleghi da internet dopo aver caricato la pagina continua a funzionare, che è la prova più semplice."
  - q: "Che lunghezza devo scegliere?"
    a: "Con tutti e quattro i gruppi, 16 caratteri danno circa 104 bit di entropia, ben oltre la portata di qualsiasi attacco brute-force. Usane 20 o più per gli account più delicati, se il sito lo consente. Scendi sotto i 12 solo se un vecchio sistema ti obbliga."
  - q: "Perché la mia password non contiene un simbolo anche se i simboli sono attivi?"
    a: "Ogni carattere è estratto in modo indipendente dall'intero insieme, quindi la password non è obbligata a contenere un carattere di ogni tipo. Con 16 caratteri succede quasi sempre. Se un sito la rifiuta perché manca un simbolo o una cifra, premi di nuovo Genera."
  - q: "Cosa significano Debole, Buona e Forte?"
    a: "Sono fasce di entropia: sotto i 60 bit è Debole, da 60 a 90 bit Buona, da 90 bit in su Forte. Poiché la password è generata a caso, il numero è esatto, a differenza dei misuratori che cercano di indovinare l'entropia di una password scritta da te."
  - q: "Devo ricordare queste password?"
    a: "No, salvale in un gestore di password e lascia che le compili lui. Per uno o due segreti da memorizzare, come la password principale del gestore, usa la modalità **Passphrase**: sei o sette parole casuali sono molto più facili da digitare e ricordare di 16 caratteri casuali, con una robustezza simile."
  - q: "Quali elenchi di parole usa la modalità passphrase?"
    a: "L'inglese usa l'EFF Large Wordlist (7.776 parole, circa 12,9 bit per parola, CC BY 4.0). Il tedesco usa l'elenco de-7776 di dys2p (7.776 parole, rilasciato in CC0 e licenze equivalenti al pubblico dominio). Italiano, spagnolo, francese e portoghese usano gli elenchi BIP-39 (2.048 parole, 11 bit per parola) come pubblicati nella libreria python-mnemonic di Trezor con licenza MIT. Sono tutti serviti da questo sito; Togli gli accenti non riduce mai l'entropia perché le parole BIP-39 restano distinte anche senza accenti."
---

## Come funziona

Il generatore costruisce un insieme dai gruppi selezionati: 26 maiuscole, 26 minuscole, 10 cifre e 29 simboli (`` !@#$%^&*()_+~`|}{[]:;?><,./-= ``), fino a **91 caratteri**. Per ogni posizione chiede alla Web Crypto API un numero casuale a 32 bit con `crypto.getRandomValues()` e lo trasforma in un carattere.

Questa trasformazione usa il **rejection sampling**. 2³² non è un multiplo di 91, quindi il semplice `casuale % 91` renderebbe alcuni caratteri leggermente più probabili degli altri. Invece, ogni valore che cade nell'ultima fetta incompleta dell'intervallo a 32 bit viene scartato ed estratto di nuovo, e ogni carattere ha esattamente la stessa probabilità.

La riga della robustezza non è una stima a occhio. Poiché ogni carattere è casuale in modo uniforme, l'entropia è esattamente **lunghezza × log₂(dimensione dell'insieme)**:

| Impostazioni | Bit per carattere | 12 car. | 16 car. | 24 car. |
|---|---|---|---|---|
| Tutti e quattro i gruppi (91) | 6,51 | 78 | 104 | 156 |
| Lettere + cifre (62) | 5,95 | 71 | 95 | 143 |
| Minuscole + cifre (36) | 5,17 | 62 | 83 | 124 |
| Solo cifre (10) | 3,32 | 40 | 53 | 80 |

Il giudizio è **Debole** sotto i 60 bit, **Buona** da 60 a 90 bit e **Forte** da 90 bit in su; la barra è piena a 128 bit. Cambiare lunghezza o una casella rigenera subito la password, quindi ciò che vedi corrisponde sempre alle impostazioni.

La copia usa la Clipboard API asincrona quando la pagina è servita in HTTPS, con un'alternativa per i browser più vecchi. La password vive solo nel campo di testo: ricarica la pagina e sparisce.

### Perché l'entropia è la misura giusta

Un attaccante che conosce perfettamente questo generatore, insieme e lunghezza compresi, deve comunque provare in media metà delle 2^bit combinazioni. A 104 bit sono circa 10³¹ tentativi: anche a 10 miliardi al secondo servirebbe molto più dell'età dell'universo. Ecco perché una password generata bene è forte *per costruzione*, mentre una password inventata è forte solo quanto è piccolo il dizionario dell'attaccante.

## Passphrase: parole casuali invece di caratteri casuali

Una passphrase è formata da alcune parole scelte **a caso** da un elenco fisso, il metodo chiamato *diceware*. La robustezza dipende solo dalla dimensione dell'elenco e dal numero di parole, mai da quanto sembrano originali: ogni parola di un elenco di 7.776 aggiunge log₂(7776) ≈ **12,9 bit**, ogni parola di un elenco di 2.048 esattamente **11 bit**.

| Parole | Elenco EFF / tedesco (7.776) | Elenchi BIP-39 (2.048) |
|---|---|---|
| 4 | 51,7 bit | 44 bit |
| 5 | 64,6 bit | 55 bit |
| 6 | 77,5 bit | 66 bit |
| 7 | 90,5 bit | 77 bit |
| 8 | 103,4 bit | 88 bit |

Le parole vengono scelte con lo stesso campionamento imparziale di `crypto.getRandomValues()` usato per le password. **Iniziali maiuscole** è deterministico e non aggiunge entropia; **Aggiungi una cifra** mette una cifra casuale dopo una parola casuale e aggiunge log₂(10 × parole) bit. L'elenco predefinito segue la lingua della pagina, e ogni elenco si può usare su qualsiasi pagina.

## Casi d'uso

- **Registrarsi a un nuovo servizio.** Genera 16 o più caratteri, salvali nel password manager e hai finito.
- **Cambiare password dopo una violazione.** Sostituisci una password riusata o trapelata con una unica e casuale, partendo dall'email, perché da lì si possono reimpostare tutte le altre.
- **Chiavi API, utenti di database e account di servizio.** Togli i simboli se una stringa di connessione o uno script di shell li digerisce male, e aumenta la lunghezza per restare sopra i 100 bit.
- **Reti Wi-Fi.** Genera una chiave di 20–30 caratteri per il router: la digiti una sola volta per dispositivo.
- **Credenziali temporanee.** Crea una password usa e getta per un account ospite o un documento condiviso, poi elimina l'account quando hai finito.

Per verificare la robustezza di una password che usi già, e se compare in una violazione di dati nota, prova [PassFort](/it/tools/pass-fort/).
