---
title: "Cifrario di Cesare: Cifra e Decifra (ROT13)"
description: "Cifra e decifra testo con il cifrario di Cesare, con ogni spostamento da 1 a 25 compreso il ROT13. Scopri come funziona e come si rompe. Gratis."
intro: "Sposta ogni lettera del testo di un numero fisso di posizioni nell'alfabeto, il cifrario che usava Giulio Cesare. Scegli uno spostamento da 1 a 25 (13 dà il **ROT13**), poi cifra o decifra. Un classico per enigmi, CTF e per capire perché i cifrari semplici non reggono."
date: 2026-02-03
lastmod: 2026-10-24
reviewed: false
keywords: ["cifrario di cesare", "decifrare cifrario di cesare", "codice di cesare", "rot13", "cifrario a scorrimento", "cifrare testo", "crittografia classica", "cifrario cesare online"]
tags: ["crittografia", "cifrario", "ctf", "strumento"]
app_category: "EducationalApplication"
tool_partial: "caesar-cipher"
howto:
  - "Scrivi o incolla il messaggio in **Testo di input**."
  - "Imposta la **Chiave di spostamento** con il cursore (1–25). Cesare usava 3; 13 è il ROT13."
  - "Premi **Cifra** per spostare le lettere in avanti, o **Decifra** per riportarle indietro della stessa quantità."
  - "Leggi il risultato in **Risultato** e premi **Copia** per metterlo negli appunti."
  - "Per forzare un messaggio sconosciuto, decifralo con ogni spostamento finché compaiono parole leggibili: ce ne sono solo 25 da provare."
faq:
  - q: "Come funziona il cifrario di Cesare?"
    a: "Ogni lettera viene sostituita da quella che si trova un numero fisso di posizioni più avanti nell'alfabeto, ricominciando da A dopo la Z. Con spostamento 3, A diventa D, B diventa E e Z diventa C. Per decifrare si torna indietro dello stesso numero."
  - q: "Cos'è il ROT13?"
    a: "Il ROT13 è il cifrario di Cesare con spostamento 13. Poiché l'alfabeto inglese ha 26 lettere, applicarlo due volte restituisce il testo originale, quindi la stessa operazione cifra e decifra. Si usava nei forum per nascondere spoiler e battute, mai per la sicurezza."
  - q: "Il cifrario di Cesare è sicuro?"
    a: "No. Le chiavi utili sono solo 25, quindi chiunque può provarle tutte a mano in pochi secondi. L'analisi delle frequenze lo rompe ancora prima: in italiano la lettera più frequente è spesso la E o la A, e nel testo cifrato compare spostata della chiave. Usalo solo per giochi e didattica."
  - q: "Cosa succede a numeri, spazi e lettere accentate?"
    a: "Restano invariati. Lo strumento sposta solo le 26 lettere latine di base A–Z e a–z, mantenendo maiuscole e minuscole. Cifre, punteggiatura, spazi e lettere come à o è passano così come sono."
  - q: "Come si decifra un cifrario di Cesare senza chiave?"
    a: "Con la forza bruta: decifra con gli spostamenti da 1 a 25 e cerca quello che produce testo leggibile. Per messaggi più lunghi conta le lettere: la più frequente corrisponde di solito alla E o alla A in italiano, e la distanza tra le due è lo spostamento."
  - q: "Il mio testo viene inviato da qualche parte?"
    a: "No. Lo spostamento viene calcolato da poche righe di JavaScript in questa pagina e non viene caricato nulla."
---

## Come funziona

Lo strumento scorre il testo un carattere alla volta e ne guarda il codice:

- le maiuscole `A–Z` (codici 65–90) vengono spostate all'interno dell'alfabeto maiuscolo;
- le minuscole `a–z` (codici 97–122) all'interno dell'alfabeto minuscolo;
- tutto il resto (cifre, spazi, punteggiatura, lettere accentate e non latine) viene copiato invariato.

Lo spostamento è aritmetica modulare sulla posizione *p* della lettera (0 per A, 25 per Z) e sulla chiave *k*:

**cifrato = (p + k) mod 26**, e la decifratura usa −k.

Poiché in JavaScript `%` può restituire numeri negativi, il codice calcola `((p + k) % 26 + 26) % 26`, che mantiene il risultato tra 0 e 25 in entrambe le direzioni. La posizione viene poi riconvertita in carattere con le maiuscole o minuscole originali.

| In chiaro | Spostamento 3 | Spostamento 13 (ROT13) |
|---|---|---|
| `HELLO` | `KHOOR` | `URYYB` |
| `Attack at dawn` | `Dwwdfn dw gdzq` | `Nggnpx ng qnja` |
| `Zebra` | `Cheud` | `Mroen` |

### Perché si rompe così facilmente

Il cifrario di Cesare ha uno spazio delle chiavi di 25. Un computer, o una persona paziente, prova ogni chiave in un attimo. E poiché ogni lettera corrisponde sempre alla stessa lettera, il testo cifrato conserva l'impronta statistica della lingua: il simbolo più frequente di un testo cifrato è quasi sempre una delle vocali più comuni spostata della chiave. Questi due difetti, spazio delle chiavi minuscolo e frequenze conservate, sono proprio ciò che i cifrari moderni come AES sono progettati per evitare.

## Casi d'uso

- **Sfide CTF ed enigmi.** Cesare e ROT13 compaiono di continuo nelle prove capture-the-flag per principianti, nelle escape room e nel geocaching.
- **Insegnare la crittografia.** Mostra agli studenti cifratura, chiavi e forza bruta con qualcosa che si fa anche su carta, poi spiega perché fallisce.
- **Nascondere spoiler.** Il ROT13 nasconde ancora una battuta o una soluzione dalla lettura accidentale.
- **Esercizi di programmazione.** Confronta la tua implementazione con questa: aritmetica modulare e gestione delle maiuscole sono gli inciampi tipici.
- **Curiosità storica.** Codifica un messaggio come facevano i generali romani, con spostamento 3.
