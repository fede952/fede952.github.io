---
title: "Verifica SPF, DKIM e DMARC di un dominio"
description: "Controlla i record SPF, DKIM e DMARC di un dominio, conta le ricerche SPF rispetto al limite di 10, verifica chiavi DKIM e BIMI e ottieni correzioni."
intro: "Inserisci un dominio per valutare la sua **autenticazione email**. Lo strumento legge il record **SPF** e conta le ricerche DNS **attraverso ogni include** rispetto al limite di 10, legge **policy DMARC**, percentuale, indirizzi dei report e allineamento, misura la **lunghezza delle chiavi DKIM** e controlla **MX** e **BIMI**. Ogni problema ha un **record di esempio** per correggerlo. Le richieste DNS vanno al resolver DNS-over-HTTPS di Cloudflare, solo quando premi Verifica."
date: 2026-10-26
lastmod: 2026-10-26
reviewed: false
keywords: ["verifica spf", "controllo dmarc", "verifica dkim", "controllo spf dkim dmarc", "record spf come verificare", "record dmarc esempio", "spf troppe ricerche dns", "lunghezza chiave dkim", "policy dmarc reject", "record bimi"]
tags: ["security", "email", "dns", "tool"]
app_category: "SecurityApplication"
tool_file: "/tools/spf-dmarc-checker/"
tool_title: "Verifica SPF, DKIM e DMARC"
tool_height: 1150
tool_sandbox: "allow-scripts allow-same-origin"
tool_allow: "clipboard-write"
howto:
  - "Scrivi un **dominio** (o incolla un indirizzo email: si usa solo la parte dopo la @)."
  - "Facoltativo: inserisci i tuoi **selettori DKIM**, separati da virgole. Senza, lo strumento prova i nomi di selettore più comuni."
  - "Premi **Verifica**. È l'unico momento in cui partono richieste DNS."
  - "Leggi il **voto** e ogni sezione: SPF con il conteggio delle ricerche e l'albero degli include, tag DMARC, chiavi DKIM, MX e BIMI."
  - "In **Correzioni suggerite**, copia i record di esempio, sostituisci le parti tra parentesi angolari e verifica con il tuo provider di posta prima di pubblicarli."
faq:
  - q: "Cosa viene inviato, e a chi?"
    a: "Quando premi Verifica, il browser invia richieste DNS per il dominio (i record TXT per SPF, _dmarc, selettori DKIM e BIMI, e i record MX) al resolver pubblico DNS-over-HTTPS di Cloudflare, cloudflare-dns.com. Come ogni richiesta web, rivela a Cloudflare il tuo indirizzo IP e lo user-agent del browser. Niente viene inviato a questo sito, e niente parte prima che tu prema il pulsante."
  - q: "Perché SPF ha un limite di 10 ricerche?"
    a: "Lo standard SPF (RFC 7208) limita a 10 per controllo i meccanismi che richiedono una ricerca DNS — include, a, mx, ptr, exists e il modificatore redirect — contati attraverso tutti gli include annidati. Chi riceve e supera il limite si ferma con un errore permanente, quindi SPF fallisce per tutta la tua posta, non solo per i mittenti in più. ip4, ip6 e all non contano."
  - q: "Perché non trova la chiave DKIM se la mia posta è firmata?"
    a: "Le chiavi DKIM stanno sotto un nome di selettore scelto dal provider (selettore._domainkey.tuodominio), e il DNS non permette di elencarle. Lo strumento prova solo alcuni nomi comuni. Trova il tuo selettore nel tag s= di un header DKIM-Signature (lo mostra l'analizzatore di header email di questo sito) e inseriscilo."
  - q: "p=none basta?"
    a: "È il primo passo giusto: ricevi i report senza toccare la consegna. Ma non impedisce a nessuno di falsificare il tuo dominio. Quando i report mostrano che i tuoi mittenti legittimi passano, passa a p=quarantine e poi a p=reject."
  - q: "Meglio ~all o -all?"
    a: "Entrambi segnano come non autorizzati i server non elencati. Con DMARC su quarantine o reject, i destinatari agiscono comunque sull'esito DMARC, quindi ~all è una scelta comune e sicura; -all è più severo, e alcuni destinatari potrebbero rifiutare il messaggio già per quello, prima di valutare DMARC."
  - q: "I record di esempio sono pronti da incollare?"
    a: "Sono punti di partenza costruiti dai tuoi record attuali. Le parti tra parentesi angolari vanno sostituite, e solo tu o il tuo provider conoscete tutti i servizi che inviano per il tuo dominio. Verifica con il provider, poi ripeti il controllo dopo l'aggiornamento del DNS."
---

## Come funziona

### SPF: contare le ricerche come fanno i destinatari

Lo strumento legge i record TXT del dominio e tiene quello che inizia con `v=spf1`. Poi lo percorre termine per termine. Ogni `include`, `a`, `mx`, `ptr`, `exists` e `redirect` aggiunge una ricerca, e ogni `include` viene a sua volta letto e percorso, quindi contano anche i provider annidati. Il totale viene confrontato con il limite di 10 della RFC 7208. Vengono segnalati anche gli include verso domini senza SPF, più di due ricerche che non restituiscono nulla, i cicli di include, il meccanismo sconsigliato `ptr` e il qualificatore di `all`.

### DMARC: policy, copertura e report

Il record in `_dmarc.<dominio>` viene analizzato tag per tag. Un sottodominio senza un proprio record eredita quello del dominio principale e la sua policy `sp=`, come fanno i destinatari. Il voto dipende dalla policy (`none`, `quarantine`, `reject`), da `pct`, dalla presenza dei report aggregati (`rua`) e dal fatto che gli indirizzi dei report su un altro dominio abbiano pubblicato il record di autorizzazione necessario (RFC 7489, sezione 7.1).

### DKIM: lunghezza della chiave dalla chiave pubblica

Per ogni selettore trovato, il valore `p=` viene decodificato e la lunghezza del modulo RSA viene letta dalla chiave. Le chiavi sotto i 1024 bit non devono essere accettate dai destinatari (RFC 8301); la lunghezza consigliata è 2048 bit. Le chiavi vuote risultano revocate, e le chiavi Ed25519 vengono riconosciute.

### MX e BIMI

I record MX indicano dove il dominio riceve la posta; un "null MX" (`0 .`) significa che non ne accetta. BIMI (`default._bimi`) è facoltativo e funziona solo con una policy DMARC che blocca al 100%.

## Casi d'uso

- **Prima di inviare newsletter** — assicurati che SPF, DKIM e DMARC passino, così la posta arriva in casella.
- **Dopo aver aggiunto un servizio di posta** — controlla che il nuovo `include:` non abbia portato SPF oltre le 10 ricerche.
- **Mettere in sicurezza un dominio** — passa DMARC da `p=none` a `p=reject` con fiducia, e proteggi i domini che non inviano mai posta.
- **Verifiche di sicurezza** — controlla la protezione dallo spoofing dei domini di un fornitore o della tua organizzazione.
- **Indagare su un'email sospetta** — guarda cosa pubblica il dominio del mittente, poi leggi il messaggio con l'[analizzatore di header email](../email-header-analyzer/).
