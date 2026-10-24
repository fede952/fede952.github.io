---
title: "Questo Link è Sicuro? Controllo Phishing"
description: "Incolla un link sospetto e scopri i trucchi di phishing nella sua struttura: IP, login nascosti con @, domini punycode, TLD a rischio. Senza aprirlo."
intro: "**LinkHazmat** analizza un URL *senza visitarlo* e segnala i trucchi strutturali su cui si basano i link di phishing: host con indirizzo IP, login nascosti con `@`, domini sosia in punycode, TLD a rischio, nomi di brand nei sottodomini e parametri di redirect. Poi ti offre link diretti a scanner di reputazione più approfonditi."
date: 2026-02-14
lastmod: 2026-10-24
reviewed: false
keywords: ["questo link è sicuro", "verificare link", "controllo link phishing", "link sospetto", "scanner url", "come capire se un link è sicuro", "riconoscere link phishing", "test sicurezza link"]
tags: ["sicurezza", "phishing", "scanner-url", "strumento"]
app_category: "SecurityApplication"
tool_partial: "link-hazmat"
howto:
  - "Copia il link sospetto *senza aprirlo*: tieni premuto o fai clic destro e scegli \"Copia indirizzo link\"."
  - "Incollalo nella casella e premi **INITIATE SCAN** (o Invio). Se manca `http://` viene aggiunto in automatico."
  - "Leggi il verdetto: **LOW RISK**, **SUSPICIOUS** o **HIGH RISK**, con ogni trucco individuato elencato in *Tricks detected*."
  - "Controlla protocollo, dominio reale ed estensione (TLD) a cui punta davvero il link: il dominio reale è spesso molto diverso da quello che suggerisce il testo del link."
  - "Per un secondo parere usa i pulsanti **VirusTotal**, **Google Transparency** o **Urlscan.io**, che aprono quei servizi con il link già inserito."
faq:
  - q: "Come capisco se un link è sicuro prima di cliccarlo?"
    a: "Guarda il dominio reale, la parte subito prima del primo `/` singolo. In `https://paypal.com.secure-login.xyz/…` il dominio è `secure-login.xyz`, non PayPal. Diffida di indirizzi IP al posto dei nomi, di una `@` nell'indirizzo, di estensioni insolite, di tanti trattini e di qualsiasi pagina che ti chieda il login dopo un'email o un SMS."
  - q: "LinkHazmat visita il link?"
    a: "No. L'URL viene solo analizzato come testo con il parser `URL` del browser; non viene scaricato nulla, quindi una pagina malevola non può caricarsi né eseguire alcunché. Una terza parte vede il link solo se premi uno dei pulsanti degli scanner esterni."
  - q: "Un link LOW RISK può essere comunque pericoloso?"
    a: "Sì. È un controllo strutturale: individua i trucchi che fanno *sembrare* legittimo un link, non se il sito dietro un dominio dall'aspetto normale sia malevolo. Un dominio appena registrato con una struttura pulita prende un punteggio basso. Nel dubbio usa gli scanner di reputazione, oppure apri il sito digitandone tu l'indirizzo."
  - q: "Cos'è un attacco punycode o omografico?"
    a: "I domini possono contenere lettere non latine, salvate in una forma ASCII che inizia con `xn--`. Gli attaccanti registrano sosia come `аpple.com` con una а cirillica, che si vede quasi identica all'originale. LinkHazmat converte l'host nella sua forma ASCII, quindi ogni etichetta `xn--` viene smascherata e segnalata."
  - q: "Perché una @ in un URL è sospetta?"
    a: "Tutto ciò che sta prima di una `@` nella parte di autorità di un URL viene trattato come nome utente, non come host. `https://www.bank.com@evil.example/` porta in realtà a `evil.example`. I link legittimi non la usano quasi mai, ed è per questo che lo strumento aggiunge due punti."
  - q: "Quali TLD vengono segnalati?"
    a: "`.xyz`, `.top`, `.gq`, `.zip`, `.mov`, `.tk`, `.ml`, `.ga`, `.cf`, `.buzz`, `.icu` e `.cam`: estensioni economiche o gratuite da registrare che compaiono in modo sproporzionato nelle segnalazioni di abuso. Molti siti onesti le usano, quindi aggiungono solo un punto."
---

## Come funziona

L'input viene analizzato con il costruttore standard `URL` del browser (anteponendo `http://` se manca lo schema). Così si ottengono protocollo, hostname in forma ASCII e query string esattamente come li interpreterebbe un browser, il che conta perché il phishing vive della differenza tra come un URL *appare* e dove *porta*.

Ogni controllo aggiunge punti a un punteggio di rischio:

| Controllo | Cosa cerca | Punti |
|---|---|---|
| Non cifrato | `http:` invece di `https:` | +1 |
| Host IP | un hostname come `185.12.4.9` invece di un dominio | +2 |
| Login nascosto | una `@` in qualsiasi punto dell'input | +2 |
| TLD a rischio | una di 12 estensioni spesso abusate | +1 |
| Dominio lungo | hostname oltre i 50 caratteri | +1 |
| Annidamento profondo | più di 4 etichette, es. `a.b.c.d.com` | +1 |
| Punycode | un'etichetta che inizia con `xn--` (sosia internazionalizzato) | +2 |
| Pieno di trattini | 3 o più trattini nell'hostname | +1 |
| Parametro di redirect | `redirect=`, `url=`, `goto=`, `next=`, `redir=` o `link=` nella query | +1 |
| Brand nel sottodominio | paypal, apple, google, microsoft, amazon, netflix, bank, secure, login, verify o account a *sinistra* del dominio registrabile | +2 |

Un punteggio di **0** è *LOW RISK*, **1–2** è *SUSPICIOUS*, **3 o più** è *HIGH RISK*. Il controllo sui brand guarda solo le etichette del sottodominio: `www.paypal.com` passa, mentre `paypal.com.account-check.xyz` (dominio registrabile `account-check.xyz`) viene segnalato. Il dominio registrabile è approssimato con le ultime due etichette, quindi suffissi composti come `.co.uk` vengono contati con un livello in meno.

I pulsanti di analisi approfondita costruiscono link alla ricerca di VirusTotal, allo stato Safe Browsing di Google e alla ricerca di urlscan.io con dominio o URL codificati. Si aprono in una nuova scheda solo quando ci clicchi.

## Casi d'uso

- **Controllare un link arrivato via email o SMS** che dice di essere la tua banca, un corriere o un servizio di streaming, prima di decidere se toccarlo.
- **Help desk e SOC.** Dai a un collega una lettura strutturale veloce di un link segnalato, poi passa agli scanner di reputazione.
- **Formazione sulla sicurezza.** Incolla esempi reali di phishing e mostra quali trucchi usa ciascuno.
- **Link da QR code.** Leggi un QR code con la fotocamera senza aprirlo, poi incolla qui l'URL.
- **Rivedere i tuoi link.** Assicurati che i link di marketing con parametri di tracciamento o redirect non sembrino phishing agli utenti più prudenti.
