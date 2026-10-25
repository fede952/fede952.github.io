---
title: "Codifica e Decodifica Base64 Online (UTF-8)"
description: "Codifica testo in Base64 o decodifica Base64 e Base64URL in testo, con pieno supporto UTF-8 per accenti ed emoji. Gratis, istantaneo, funziona nel browser."
intro: "Converti testo in **Base64** e viceversa. La codifica è sicura per UTF-8 e la decodifica accetta anche la variante **Base64URL** usata nei JWT e nelle API web, con o senza padding `=`. Nulla di ciò che incolli lascia questa pagina."
date: 2026-02-03
lastmod: 2026-10-24
reviewed: false
keywords: ["codifica base64", "decodifica base64", "base64 decoder", "base64 online", "decodificare base64url", "base64 in testo", "base64 utf-8", "convertitore base64"]
tags: ["codifica", "strumenti-sviluppo", "base64", "strumento"]
app_category: "DeveloperApplication"
tool_partial: "base64-converter"
howto:
  - "Scrivi o incolla in **Testo di input**: testo semplice da codificare o una stringa Base64 da decodificare."
  - "Premi **Codifica in Base64** per trasformare il testo in Base64. Accenti, alfabeti non latini ed emoji vengono codificati in UTF-8."
  - "Premi **Decodifica da Base64** per riportare il Base64 a testo. Sono accettati Base64 standard, Base64URL (`-` e `_`), padding mancante e a capo."
  - "Leggi il risultato in **Risultato** e premi **Copia** per metterlo negli appunti."
  - "Se i byte decodificati non sono UTF-8 valido, lo strumento lo segnala: probabilmente si tratta di dati binari (un'immagine, un file compresso o una chiave) e non di testo."
faq:
  - q: "A cosa serve il Base64?"
    a: "Il Base64 rappresenta dati binari con 64 caratteri ASCII stampabili, così possono viaggiare in sistemi che gestiscono solo testo: allegati email (MIME), data URL in HTML e CSS, payload JSON, header di autenticazione HTTP Basic, Secret di Kubernetes e le tre parti di un JSON Web Token."
  - q: "Il Base64 è una cifratura?"
    a: "No. È una codifica senza chiave: chiunque può decodificarla all'istante, come dimostra questa pagina. Non usare mai il Base64 per nascondere password o segreti; i Secret di Kubernetes, per esempio, sono solo codificati in Base64, non cifrati, a meno di attivare la cifratura a riposo."
  - q: "Che differenza c'è tra Base64 e Base64URL?"
    a: "Il Base64URL (RFC 4648, sezione 5) sostituisce `+` con `-` e `/` con `_` perché il risultato sia sicuro in URL e nomi di file, e di solito elimina il padding `=`. Lo usano i JWT e molte API. Questo strumento decodifica entrambi; in codifica produce Base64 standard."
  - q: "Perché il testo decodificato è illeggibile?"
    a: "O l'input non era testo fin dall'inizio (per esempio un'immagine o uno stream gzip), oppure il testo originale era codificato con un altro set di caratteri, come Latin-1 invece di UTF-8. Lo strumento decodifica in UTF-8 e ti avvisa quando i byte non sono UTF-8 valido."
  - q: "Perché il Base64 è circa un terzo più grande dell'originale?"
    a: "Ogni 3 byte di input diventano 4 caratteri Base64, perché ogni carattere porta 6 bit (2⁶ = 64). È un aumento del 33%, più fino a due caratteri `=` di padding finale. Un'immagine da 30 KB diventa una data URL da 40 KB."
  - q: "Il testo che incollo viene inviato da qualche parte?"
    a: "No. Codifica e decodifica usano le funzioni integrate del browser `btoa`, `atob`, `TextEncoder` e `TextDecoder` dentro questa pagina. Non viene caricato né salvato nulla."
---

## Come funziona

### Codifica

La funzione `btoa()` di JavaScript capisce solo i caratteri dell'intervallo Latin-1, quindi chiamarla direttamente su `"Città €"` genera un errore. Lo strumento lo evita codificando nel modo corretto:

1. `TextEncoder` converte il testo in **byte UTF-8**: `à` diventa `C3 A0`, `€` diventa `E2 82 AC`.
2. Ogni byte viene trasformato in un carattere da un byte, e `btoa()` converte quella stringa di byte in Base64.

Il Base64 lavora su gruppi di **3 byte = 24 bit**, divisi in quattro valori da 6 bit, ognuno associato a un carattere dell'alfabeto `A–Z a–z 0–9 + /`. Quando la lunghezza dell'input non è un multiplo di 3, l'ultimo gruppo viene completato con `=`:

| Testo | Byte UTF-8 | Base64 |
|---|---|---|
| `Man` | `4D 61 6E` | `TWFu` |
| `Ma` | `4D 61` | `TWE=` |
| `M` | `4D` | `TQ==` |
| `é` | `C3 A9` | `w6k=` |

### Decodifica

La decodifica inverte il processo con un po' di tolleranza per l'input reale:

- Vengono rimossi spazi e a capo (il MIME manda a capo il Base64 ogni 76 caratteri).
- I caratteri **Base64URL** `-` e `_` vengono riportati a `+` e `/` e il padding `=` mancante viene ripristinato, così puoi incollare un segmento di JWT così com'è.
- `atob()` trasforma il Base64 in byte e `TextDecoder` con `fatal: true` li interpreta come UTF-8. Se i byte non sono UTF-8 valido, lo strumento mostra comunque una decodifica approssimativa ma avvisa che probabilmente si tratta di dati binari.
- Una stringa la cui lunghezza divisa per 4 dà resto 1 non può mai essere Base64 valido, e viene rifiutata con un messaggio chiaro.

## Casi d'uso

- **Leggere un JWT a mano.** Incolla il segmento centrale di un token per vederne i claim JSON (per verificare la firma usa JWT Inspector).
- **Kubernetes e Docker.** Decodifica i valori di un manifest Secret, o codifica un valore prima di metterlo in `data:`.
- **Autenticazione HTTP Basic.** Decodifica un header `Authorization: Basic …` per vedere l'`utente:password` che contiene, o costruiscine uno per una richiesta di test.
- **Data URL ed email.** Ispeziona URI `data:` e parti MIME nel sorgente grezzo di un'email.
- **Debug di API.** Molte API codificano in Base64 campi binari o JSON annidato; decodificali per vedere cosa è stato davvero inviato.
