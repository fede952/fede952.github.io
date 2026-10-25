---
title: "Qual è il Mio IP? Test Privacy del Browser"
description: "Scopri IP pubblico, provider e posizione, verifica l'esposizione dell'IP locale via WebRTC, GPU e impronta del dispositivo, con un punteggio privacy."
intro: "**NetGuard** mostra cosa può sapere di te qualsiasi sito nel momento in cui ti colleghi: indirizzo IP pubblico, provider e posizione approssimativa, più i segnali del dispositivo che il browser fornisce gratis. Un clic, un punteggio privacy e spiegazioni chiare."
date: 2026-02-03
lastmod: 2026-10-24
reviewed: false
keywords: ["qual è il mio ip", "il mio indirizzo ip", "test ip leak", "test webrtc leak", "test privacy browser", "verificare vpn", "cosa sanno i siti di me", "punteggio privacy"]
tags: ["privacy", "rete", "vpn", "strumento"]
app_category: "SecurityApplication"
tool_file: "/tools/netguard/"
tool_title: "NetGuard: test privacy del browser e IP leak"
tool_height: 1100
tool_sandbox: "allow-scripts allow-same-origin allow-popups allow-popups-to-escape-sandbox"
howto:
  - "Premi **Run Privacy Scan**. La scansione dura circa quattro secondi, quasi tutti per il controllo WebRTC."
  - "Leggi **Network & Location**: indirizzo IP pubblico, provider e città che ogni server web vede quando ti colleghi, ricavati tramite ipwho.is."
  - "Guarda la scheda **WebRTC**. Verde significa che il browser non ha esposto un indirizzo di rete privato; rosso elenca gli indirizzi trapelati."
  - "Scorri le schede dell'impronta (sistema operativo, browser, schermo, GPU, lingua e fuso orario, batteria): ognuna è leggibile da qualsiasi sito senza chiedere permessi."
  - "Confronta il **Privacy Score** prima e dopo una modifica, per esempio attivando una VPN, cambiando browser o bloccando WebGL, e premi **Scan Again**."
faq:
  - q: "Qual è il mio indirizzo IP e chi può vederlo?"
    a: "L'IP pubblico è l'indirizzo che il tuo provider (o la VPN) assegna alla connessione. Lo vedono tutti i siti, i server pubblicitari e le CDN che contatti, perché serve per rispedirti la pagina. Di solito rivela il provider e la città o la regione, raramente la via esatta."
  - q: "Una VPN nasconde il mio IP a questo test?"
    a: "Sì: le schede IP, provider e posizione mostreranno i dati del server VPN invece dei tuoi, che è lo scopo di una VPN. Il punteggio però non sa se un indirizzo appartiene a una VPN e toglie gli stessi punti per qualsiasi IP visibile: confronta le schede, non solo il numero."
  - q: "Cos'è un WebRTC leak?"
    a: "WebRTC permette ai browser di creare connessioni peer-to-peer per le videochiamate. Per farlo raccoglie gli \"ICE candidate\", gli indirizzi di rete a cui il dispositivo è raggiungibile. I browser più vecchi esponevano così a qualsiasi pagina l'indirizzo LAN privato del dispositivo (come 192.168.1.23). NetGuard verifica proprio questo; i browser moderni ora lo nascondono dietro un nome casuale `.local`."
  - q: "NetGuard può dirmi se la mia VPN fa trapelare il vero IP via WebRTC?"
    a: "Non del tutto. Il controllo gira senza server STUN, quindi rivela gli indirizzi di rete locali ma non chiede a un server esterno come appare il tuo indirizzo pubblico via WebRTC. Per testare quella specifica falla delle VPN, attiva la VPN, apri un test WebRTC dedicato basato su STUN e confronta l'indirizzo pubblico che riporta con l'IP mostrato qui."
  - q: "Perché si vede il modello della mia GPU?"
    a: "Tramite l'estensione WebGL `WEBGL_debug_renderer_info` una pagina può leggere la stringa esatta del renderer grafico, per esempio un modello di GPU NVIDIA o Apple. Insieme a dimensioni dello schermo, fuso orario e lingua restringe il campo a un piccolo gruppo di dispositivi. Alcuni browser restituiscono un valore generico o lo bloccano, e NetGuard lo segnala come sicuro."
  - q: "Lo strumento salva o invia i miei dati?"
    a: "Dal browser parte una sola richiesta: quella a ipwho.is, che restituisce il tuo IP pubblico e la sua posizione, una richiesta che qualsiasi sito potrebbe fare. Tutto il resto viene letto e mostrato in locale, e nulla viene salvato quando chiudi la pagina."
---

## Come funziona

La scansione esegue cinque controlli in sequenza, tutti dentro la pagina, e poi li trasforma in un punteggio.

**1. Identità di rete.** Il browser chiama `https://ipwho.is/`, un'API pubblica di geolocalizzazione IP. La risposta contiene l'indirizzo da cui è partita la richiesta, il provider o l'organizzazione che lo possiede e paese, città e coordinate approssimative di quell'indirizzo. Sono le stesse informazioni che qualsiasi server web ricava dalla tua connessione, per questo la scheda è segnata come avviso.

**2. Qualità della connessione.** Dove esiste la **Network Information API** (browser basati su Chromium), `navigator.connection` riporta la banda stimata in Mbps, un tipo di connessione effettivo come `4g` e il tempo di andata e ritorno. Firefox e Safari non la espongono, e la scheda lo dice.

**3. Impronta del dispositivo.** NetGuard legge i segnali che gli script di fingerprinting raccolgono più spesso:

- sistema operativo e versione del browser ricavati dalla stringa `User-Agent`, più `navigator.platform`;
- risoluzione dello schermo, rapporto pixel del dispositivo, dimensioni della finestra e profondità di colore;
- **renderer e produttore della GPU**, da un contesto WebGL tramite l'estensione `WEBGL_debug_renderer_info`;
- `navigator.language` e il fuso orario da `Intl.DateTimeFormat().resolvedOptions()`;
- livello e stato di carica della batteria con `navigator.getBattery()`, dove il browser la implementa ancora.

**4. Controllo indirizzi locali via WebRTC.** La pagina crea una `RTCPeerConnection` senza server ICE, apre un data channel e genera un'offerta. Il browser emette allora i candidati ICE *host*, ognuno con un indirizzo di rete. NetGuard raccoglie gli indirizzi IPv4 ignorando i nomi mDNS che finiscono in `.local`, usati dai browser moderni per nascondere il vero indirizzo LAN. Ogni indirizzo raccolto viene elencato come esposto. Dopo quattro secondi il controllo termina.

**5. Punteggio privacy.** Il punteggio parte da 100 e perde punti per ogni esposizione trovata:

| Segnale | Punti |
|---|---|
| IP pubblico e posizione rilevabili | −30 |
| IP privato esposto via WebRTC | −20 |
| Sistema, browser e schermo leggibili | −10 |
| Modello esatto della GPU leggibile | −10 |
| Lingua e fuso orario leggibili | −5 |
| Stato della batteria leggibile | −5 |

Chrome su desktop fa di solito 40 (nel nostro test esattamente così); i browser che nascondono la stringa della GPU o non implementano la Battery API prendono 5–15 punti in più. Il numero serve a far ragionare più che a misurare in laboratorio: contano le singole schede.

## Casi d'uso

- **Verificare che la VPN sia attiva.** Collegala e avvia la scansione: IP, provider e città devono essere quelli della VPN, non della tua connessione di casa.
- **Vedere cosa scopre un sito prima di registrarti.** Le schede sono esattamente ciò che uno script di analytics o pubblicitario può leggere alla prima visita.
- **Confrontare i browser.** Avvia la scansione in Chrome, Firefox, Brave e Safari: le schede GPU, batteria e connessione cambiano parecchio.
- **Capire un blocco geografico.** Se un sito di streaming ti crede nel paese sbagliato, la scheda della posizione mostra in quale paese sembra trovarsi il tuo IP.
- **Spiegare le basi.** Una demo di due minuti con NetGuard spiega indirizzi IP, fingerprinting e WebRTC meglio di una presentazione. Per un'analisi più approfondita dell'impronta, prova GhostPrint.
