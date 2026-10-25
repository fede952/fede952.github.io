---
title: "Messaggio cifrato con password in un link"
description: "Cifra un messaggio nel browser con AES-256 e una passphrase e condividilo come link. Il testo non viene mai caricato: esiste solo dentro il link."
intro: "Scrivi un messaggio, scegli una passphrase e ottieni un **link** che contiene il messaggio **cifrato con AES-256-GCM**. Invia link e passphrase **su canali diversi**; chi lo riceve apre il link e lo decifra nel proprio browser. Non viene caricato né salvato nulla: il testo cifrato viaggia dentro il link stesso, nella parte dopo `#` che i browser non inviano mai a un server."
date: 2026-10-26
lastmod: 2026-10-26
reviewed: false
keywords: ["messaggio cifrato link", "inviare messaggio criptato", "cifrare testo online", "messaggio protetto da password", "condividere password in modo sicuro", "inviare nota segreta", "criptare messaggio con password", "link messaggio privato"]
tags: ["security", "privacy", "encryption", "tool"]
app_category: "SecurityApplication"
tool_file: "/tools/encrypted-message/"
tool_title: "Link con messaggio cifrato"
tool_height: 900
tool_sandbox: "allow-scripts allow-same-origin"
tool_allow: "clipboard-write"
howto:
  - "Scrivi il **messaggio**: una password del Wi-Fi, un codice del portone, una breve nota privata."
  - "Inserisci una **passphrase** di almeno 8 caratteri, oppure premi **Genera** per averne una casuale."
  - "Premi **Crea link cifrato** e **Copia link**."
  - "Invia il link su un canale (per esempio l'email) e la **passphrase su un altro** (una telefonata, un'altra app di messaggi). Mai entrambi nello stesso messaggio."
  - "Chi riceve apre il link, inserisce la passphrase e legge il messaggio nel proprio browser."
faq:
  - q: "Il mio messaggio viene caricato da qualche parte?"
    a: "No. La cifratura avviene nel browser con la Web Crypto API. Il messaggio cifrato viene messo nel link dopo il simbolo #, e i browser non inviano quella parte al server quando il link viene aperto. Questo sito non riceve mai il messaggio, la passphrase o il frammento del link, quindi non c'è nulla di salvato che possa trapelare o essere cancellato."
  - q: "Il link si autodistrugge dopo la lettura?"
    a: "No, e nessuno strumento senza un server può prometterlo. Il link è il messaggio cifrato, quindi funziona finché qualcuno ne ha una copia: in una casella di posta, in una chat, in un backup. Trattalo come il segreto stesso: chiunque abbia link e passphrase può leggerlo. Se ti serve un messaggio che sparisce, usa un servizio che lo salva su un server e lo cancella dopo la lettura, accettando di fidarti di quel server."
  - q: "Quanto è robusta la cifratura?"
    a: "Il messaggio è cifrato con AES-256 in modalità GCM, che rileva anche qualsiasi modifica al link. La chiave è derivata dalla passphrase con PBKDF2-HMAC-SHA-256 e 600.000 iterazioni, con salt e IV casuali per ogni messaggio. Il punto debole è la passphrase: una corta o prevedibile può essere indovinata per forza bruta da chiunque abbia il link, quindi usane una lunga o il pulsante Genera."
  - q: "E se la passphrase è sbagliata o il link è tagliato?"
    a: "La decifratura fallisce con un messaggio chiaro. La cifratura autenticata non distingue una passphrase sbagliata da un link modificato, quindi controlla entrambi. Alcune app tagliano i link molto lunghi: lo strumento ti avvisa sopra i 2.000 caratteri circa."
  - q: "Perché inviare la passphrase a parte?"
    a: "Perché il link da solo è inutile senza. Se viaggiano insieme nella stessa email o chat, chiunque possa leggere quella conversazione, ora o in futuro, per esempio dopo il furto di un account, può leggere anche il messaggio."
  - q: "Posso vedere cosa fa lo strumento?"
    a: "Sì. Il codice gira nel browser e si legge con gli strumenti per sviluppatori. Nella scheda Rete puoi anche verificare che creare e aprire un link non invii nessuna richiesta con il tuo messaggio."
---

## Come funziona

### Cifratura nel browser

Quando premi **Crea link cifrato**, la pagina genera un salt casuale da 16 byte e un IV casuale da 12 byte, ricava dalla passphrase una chiave da 256 bit con **PBKDF2-HMAC-SHA-256** (600.000 iterazioni) e cifra il messaggio con **AES-256-GCM**. Salt, IV e testo cifrato con il suo tag di autenticazione vengono uniti, codificati in Base64url e messi dopo `#v1.` nel link.

### Perché il messaggio non arriva mai a un server

La parte di un URL dopo `#` è il **frammento**. I browser la tengono sul dispositivo: non viene inviata nella richiesta della pagina e non finisce nell'header `Referer`. Il link apre una pagina minima di questo sito, senza pubblicità né statistiche, che legge il frammento, lo toglie dalla barra degli indirizzi e chiede la passphrase. La decifratura avviene sul dispositivo di chi riceve.

### Da cosa non protegge

- **Chi ha sia il link sia la passphrase** — è così che lo legge il destinatario, ed è così che potrebbe leggerlo chiunque altro.
- **Una passphrase debole** — chi ha il link può provare passphrase offline alla velocità del suo hardware; le 600.000 iterazioni rendono ogni tentativo lento, non impossibile.
- **Un dispositivo compromesso** — un malware sul dispositivo di chi invia o di chi riceve può leggere il messaggio prima della cifratura o dopo la decifratura.
- **Le copie del link** — caselle di posta, chat e backup lo conservano. Non c'è modo di revocarlo.

## Casi d'uso

- **Condividere una password o la chiave del Wi-Fi** con un collega o un ospite senza lasciarla leggibile nella cronologia della chat.
- **Inviare il codice del portone o il PIN dell'allarme** a un corriere o a chi bada alla casa.
- **Passare un codice di recupero o una chiave API** a un collega via email, con la passphrase detta al telefono.
- **Lasciare una nota privata** in un posto pubblico — un ticket, un forum, un documento condiviso — che solo chi ha la passphrase può leggere.
- **Prima di inviare**, controlla quanto è difficile indovinare la tua passphrase con [PassFort](../pass-fort/).
