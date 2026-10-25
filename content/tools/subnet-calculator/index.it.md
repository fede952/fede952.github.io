---
title: "Calcolatore subnet IPv4/IPv6, CIDR e VLSM"
description: "Calcola rete, broadcast, intervallo di host, maschera e wildcard di qualsiasi CIDR IPv4 o IPv6 e suddividi un blocco in subnet uguali o VLSM. Nel browser."
intro: "Un **calcolatore di subnet** per IPv4 e IPv6: scrivi un indirizzo con prefisso o maschera e ottieni subito rete, broadcast, intervallo di host utilizzabili, netmask, wildcard e numero di host, con la vista binaria. Una terza scheda suddivide un blocco in subnet uguali o in subnet VLSM dimensionate sugli host."
date: 2026-10-25
lastmod: 2026-10-25
reviewed: false
keywords: ["calcolatore subnet", "calcolo subnet", "calcolatore cidr", "subnet mask calcolo", "calcolatore subnet ipv6", "calcolatore vlsm", "wildcard mask", "calcolo indirizzo di rete"]
tags: ["networking", "strumenti-sviluppatori", "ipv4", "ipv6", "tool"]
app_category: "DeveloperApplication"
tool_file: "/tools/subnet-calculator/"
tool_title: "Calcolatore di subnet per IPv4, IPv6 e VLSM"
tool_height: 900
tool_sandbox: "allow-scripts allow-same-origin"
tool_allow: "clipboard-write"
howto:
  - "Nella scheda **IPv4** scrivi un indirizzo con prefisso (`10.0.0.5/8`), con netmask puntata (`172.16.5.4 255.255.240.0`) o con wildcard in stile Cisco (`192.168.1.1 0.0.0.255`). Un indirizzo senza prefisso vale `/32`."
  - "Leggi i risultati mentre scrivi: rete, broadcast, primo e ultimo host utilizzabile, netmask, wildcard, host utilizzabili e indirizzi totali, e il tipo di indirizzo (privato, pubblico, CGNAT, link-local…)."
  - "Guarda la tabella **Binario**: i bit di rete sono evidenziati e quelli di host attenuati, così vedi esattamente dove il prefisso taglia l'indirizzo."
  - "Nella scheda **IPv6** incolla un indirizzo completo o compresso con prefisso: ottieni la forma compressa secondo la RFC 5952, la forma estesa, il primo e l'ultimo indirizzo del prefisso e quante reti /64 contiene."
  - "In **Suddividi (VLSM)** inserisci il blocco da dividere e scegli **In subnet uguali** (quante) oppure **Per numero di host (VLSM)** (un elenco come `100, 50, 20, 2`). Copia un valore con il suo pulsante **Copia** o l'intero piano con **Copia tabella**."
faq:
  - q: "Perché una /24 ha 254 host utilizzabili e non 256?"
    a: "Una /24 ha 256 indirizzi, ma il primo è l'indirizzo di rete e l'ultimo quello di broadcast: nessuno dei due si può assegnare a un host, quindi ne restano 254. La stessa regola (totale meno due) vale per ogni prefisso fino a /30."
  - q: "Come vengono gestite /31 e /32?"
    a: "Una /31 è trattata come collegamento punto-punto secondo la RFC 3021: entrambi gli indirizzi sono utilizzabili e non c'è broadcast. Una /32 è un singolo host, usata per loopback, route verso host e regole firewall. Gli apparati più vecchi che non supportano la RFC 3021 richiedono una /30 per un collegamento."
  - q: "Cos'è una wildcard mask?"
    a: "L'inverso bit a bit della netmask: 255.255.255.0 diventa 0.0.0.255. Le ACL Cisco e i comandi network di OSPF usano le wildcard, dove un bit 0 significa \"deve coincidere\" e un bit 1 \"qualsiasi valore\". Puoi scrivere direttamente una wildcard nel campo IPv4: il calcolatore la converte nel prefisso."
  - q: "Cosa significa VLSM e perché le subnet più grandi vengono assegnate per prime?"
    a: "Variable Length Subnet Masking permette a ogni subnet di avere un proprio prefisso: una LAN da 100 host riceve una /25, un collegamento punto-punto una /31. Assegnare dalla richiesta più grande alla più piccola mantiene ogni subnet allineata al proprio confine senza buchi sprecati; i risultati vengono poi mostrati nell'ordine in cui li hai scritti."
  - q: "Perché dividendo in 3 subnet ne ottengo 4?"
    a: "La suddivisione in parti uguali prende in prestito bit di host e ogni bit raddoppia il numero di subnet: 1 bit ne dà 2, 2 bit ne danno 4. Tre subnet richiedono quindi 2 bit, che producono 4 subnet. Usa la modalità VLSM se vuoi esattamente il numero di subnet richiesto, ognuna dimensionata sui propri host."
  - q: "Quale prefisso IPv6 deve usare una LAN?"
    a: "Una /64. L'autoconfigurazione stateless (SLAAC) e molte funzioni di IPv6 presuppongono un identificativo di interfaccia a 64 bit. Di solito una sede riceve una /48 o una /56 e la divide in /64; il calcolatore mostra quante reti /64 entrano nel prefisso inserito."
  - q: "Ciò che scrivo viene inviato a un server?"
    a: "No. Tutti i calcoli li esegue un piccolo modulo JavaScript nel tuo browser; la pagina non fa richieste con i tuoi dati, quindi puoi usarla anche con piani di indirizzamento interni."
---

## Come funziona

### Aritmetica IPv4

Un indirizzo IPv4 è un numero a 32 bit. Il calcolatore legge i quattro ottetti (rifiutando valori oltre 255 e zeri iniziali ambigui come `010`), costruisce la netmask dal prefisso impostando i primi *n* bit e poi lavora con semplici operazioni bit a bit:

- **Indirizzo di rete** = indirizzo AND maschera.
- **Wildcard** = NOT maschera.
- **Indirizzo di broadcast** = rete OR wildcard.
- **Host utilizzabili** = 2^(32 − prefisso) − 2, con le due eccezioni descritte nelle FAQ: una /31 ha due indirizzi utilizzabili (RFC 3021) e una /32 uno solo.

Se scrivi una maschera puntata deve essere *contigua*: uni seguiti da zeri. `255.255.240.0` è accettata come /20, `255.0.255.0` viene rifiutata. Se il valore non è una netmask valida ma è una wildcard valida (zeri seguiti da uni), viene letto come wildcard: anche `0.0.15.255` significa /20.

Il tipo di indirizzo deriva dai registri IANA per usi speciali: reti private RFC 1918 (10/8, 172.16/12, 192.168/16), spazio condiviso per il NAT di operatore (100.64/10, RFC 6598), loopback (127/8), link-local (169.254/16), i tre intervalli di documentazione, multicast (224/4) e spazio riservato.

### IPv6

Gli indirizzi IPv6 sono numeri a 128 bit, gestiti come `BigInt` JavaScript per non perdere precisione. Il parser accetta la forma completa, la compressione `::` (una sola volta per indirizzo) e una coda IPv4 come `::ffff:192.0.2.1`. L'output segue la **RFC 5952**, la forma testuale canonica: esadecimale minuscolo, nessuno zero iniziale nei gruppi e la sequenza più lunga di due o più gruppi a zero sostituita da `::` (la più a sinistra quando due sequenze hanno la stessa lunghezza). Un singolo gruppo a zero non viene mai compresso.

Per un prefisso, il primo indirizzo è l'indirizzo AND la maschera, l'ultimo ha tutti i bit di host a uno e la dimensione è 2^(128 − prefisso). In IPv6 non esiste il broadcast, quindi non c'è il "meno due".

### Suddividere un blocco

*In subnet uguali* aggiunge ⌈log₂ n⌉ bit al prefisso ed elenca tutte le subnet risultanti (fino a 1.024 righe). *VLSM* calcola per ogni numero di host il prefisso più piccolo che lo contiene, ordina le richieste dalla più grande alla più piccola e assegna ciascuna al primo indirizzo allineato alla sua dimensione. Se una richiesta non entra nello spazio rimasto ricevi un errore che la indica, invece di un piano con sovrapposizioni.

## Casi d'uso

- **Progettare un piano di indirizzamento.** Dividi una /22 per una nuova sede in VLAN utenti, voce, stampanti e management dimensionate sul numero di persone, poi incolla la tabella nella documentazione.
- **Scrivere regole firewall e ACL.** Ottieni la rete/prefisso o la wildcard esatta per un object group e verifica che una /20 copra davvero l'intervallo che pensi.
- **Troubleshooting.** Due host non si parlano: inserisci entrambi gli indirizzi con la loro maschera e controlla se sono davvero nella stessa subnet.
- **Reti cloud.** Pianifica i CIDR di VPC e subnet senza sovrapposizioni, ricordando che i provider cloud riservano alcuni indirizzi per subnet oltre a rete e broadcast.
- **Studio ed esami.** Verifica gli esercizi di subnetting per CCNA, Network+ o colloqui di lavoro: la vista binaria mostra perché il risultato è quello.
