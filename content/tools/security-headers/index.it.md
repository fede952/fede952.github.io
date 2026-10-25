---
title: "Analizzatore header di sicurezza e CSP"
description: "Incolla gli header di risposta HTTP o una Content-Security-Policy per trovare header mancanti, regole CSP deboli e cookie insicuri, con la correzione. Offline."
intro: "Incolla gli **header di risposta** di una pagina — da `curl -sI` o dai DevTools del browser — oppure una **Content-Security-Policy** da sola. L'analizzatore controlla **HSTS**, **CSP**, **X-Content-Type-Options**, la protezione dall'inserimento in frame, **Referrer-Policy**, **Permissions-Policy**, **COOP**, **CORS** e ogni **Set-Cookie**, spiega ogni problema e indica la correzione. Non fa **nessuna richiesta di rete**: legge solo ciò che incolli, quindi funziona anche per siti di staging e intranet."
date: 2026-10-25
lastmod: 2026-10-25
reviewed: false
keywords: ["controllo header di sicurezza", "csp evaluator", "verifica content security policy", "header di sicurezza http", "analizzatore csp", "controllo hsts", "verificare header risposta", "x-frame-options"]
tags: ["sicurezza", "csp", "http", "tool"]
app_category: "SecurityApplication"
tool_file: "/tools/security-headers/"
tool_title: "Analizzatore header di sicurezza e CSP"
tool_height: 1000
tool_sandbox: "allow-scripts allow-same-origin"
tool_allow: "clipboard-write"
howto:
  - "Copia gli header di risposta della pagina da controllare: esegui `curl -sI https://example.com` in un terminale oppure apri DevTools → **Rete**, ricarica, seleziona la richiesta della pagina e copia gli **Header di risposta**."
  - "Incollali in **Header di risposta o CSP**. Puoi anche incollare solo una policy (`default-src 'self'; …`) o un tag `<meta http-equiv=\"Content-Security-Policy\">`."
  - "Il risultato appare mentre incolli: un voto, poi tutti i risultati ordinati da **Grave** a **OK**, ognuno con l'header a cui si riferisce e cosa cambiare."
  - "Sotto **Content-Security-Policy** ogni direttiva è elencata con le sue sorgenti; quelle rischiose sono evidenziate in rosso o ambra, quelle sicure in verde."
  - "Premi **Copia report** per incollare i risultati in un ticket o in una pull request. Prova **Esempio debole** ed **Esempio robusto** per vedere la differenza."
faq:
  - q: "Lo strumento si collega al mio sito?"
    a: "No. Non scarica alcun URL: analizza solo il testo che incolli, nel browser. Così il tuo server non finisce nei log di terzi e puoi controllare siti non pubblici, come staging, intranet o localhost."
  - q: "Perché incollare gli header invece di inserire un URL?"
    a: "Leggere un URL da una pagina web è bloccato dalle regole CORS del browser, a meno che non lo faccia un server per te, e quel server vedrebbe ogni sito che provi. Incollare l'output di `curl -sI` è altrettanto rapido e resta tutto in locale."
  - q: "Cosa rende debole una Content-Security-Policy?"
    a: "I problemi tipici sono `'unsafe-inline'` in script-src (fa girare gli script inline iniettati), le sorgenti di schema come `https:` o `data:` e il jolly `*` (ammettono script da quasi ovunque), CDN in lista che ospitano endpoint JSONP o il vecchio AngularJS, e l'assenza di object-src o base-uri. Una ricerca di Google ha mostrato che la maggior parte delle policy basate su liste di host si può aggirare; i nonce con 'strict-dynamic' evitano il problema."
  - q: "Cos'è una CSP rigorosa?"
    a: "Una policy che ammette gli script tramite un nonce casuale (o un hash) invece che per host, più `'strict-dynamic'` perché gli script fidati possano caricarne altri. È l'approccio raccomandato da Google e OWASP contro gli XSS. L'esempio in \"Come funziona\" è un buon punto di partenza: pubblicalo prima come Content-Security-Policy-Report-Only e correggi ciò che segnala."
  - q: "Come viene calcolato il voto?"
    a: "Si parte da 100 e si tolgono 20 punti per ogni problema grave, 10 per ogni medio e 4 per ogni lieve; note informative e controlli superati non costano nulla. A+ richiede nessun problema grave o medio. Il voto è un riassunto veloce, non una certificazione: leggi i risultati, perché l'impatto dipende dal tuo sito."
  - q: "Servono ancora X-Frame-Options e X-XSS-Protection?"
    a: "Nei browser attuali frame-ancestors della CSP sostituisce X-Frame-Options, ma inviarli entrambi non fa danni e copre i browser vecchi, quindi lo strumento accetta l'uno o l'altro. X-XSS-Protection è obsoleto: i browser hanno rimosso il filtro che controllava, quindi lo strumento consiglia di rimuoverlo o di inviare 0."
  - q: "Quali attributi dei cookie controlla?"
    a: "Secure (inviato solo in HTTPS), HttpOnly (nascosto a JavaScript), SameSite (limita l'invio tra siti, una difesa dal CSRF) e le regole dei prefissi __Host- e __Secure-. Un cookie con SameSite=None ma senza Secure viene rifiutato dai browser ed è segnalato come grave."
---

## Come funziona

### Incolla, analizza, controlla

Il testo incollato viene diviso in righe di header. Vengono gestite le righe di stato come `HTTP/2 200`, gli pseudo-header di HTTP/2 e le righe spezzate; se incolli una catena di redirect, viene analizzata solo l'ultima risposta. Gli header ripetuti come `Set-Cookie` vengono controllati uno per uno. Se il testo inizia con una direttiva CSP, o è un tag `<meta>` CSP, viene analizzata solo la policy.

Ogni header viene poi confrontato con il comportamento attuale dei browser e con le raccomandazioni di OWASP, MDN e della specifica CSP. Ogni risultato ha una gravità, l'header a cui si riferisce e una correzione concreta.

### I controlli sulla CSP

La policy viene scomposta in direttive e sorgenti. L'analizzatore individua quale direttiva governa davvero gli script (`script-src`, o `default-src` se manca) e i plugin (`object-src` eredita da `default-src`; `base-uri` e `form-action` non ereditano affatto). Segnala `'unsafe-inline'` e `'unsafe-eval'`, i jolly, le sorgenti di schema, gli host in HTTP, gli host in lista noti per offrire JSONP o versioni arbitrarie di librerie, i nonce corti, `'strict-dynamic'` senza nonce e gli errori di sintassi che i browser ignorano in silenzio: parole chiave senza apici (`self` invece di `'self'`), punti e virgola mancanti, direttive duplicate, sconosciute e deprecate.

### Una policy rigorosa da cui partire

```text
Content-Security-Policy:
  script-src 'nonce-{RANDOM}' 'strict-dynamic';
  object-src 'none';
  base-uri 'none';
  form-action 'self';
  frame-ancestors 'self'
```

Genera un nonce casuale nuovo (almeno 128 bit) per ogni risposta e aggiungi `nonce="{RANDOM}"` a ogni tag `<script>`. Inviala prima come `Content-Security-Policy-Report-Only`, correggi ciò che si rompe, poi rendila effettiva.

## Casi d'uso

- **Prima del lancio.** Controlla gli header di un sito di staging, che gli scanner online non possono raggiungere.
- **Pull request e audit.** Incolla gli header prima e dopo una modifica e copia il report nella review.
- **Imparare la CSP.** Scopri perché ogni sorgente di una policy è o non è un rischio, direttiva per direttiva.
- **Note di pentest e bug bounty.** Trasforma una risposta catturata in un elenco di problemi sugli header con le correzioni.
- **Revisione dei cookie.** Verifica che i cookie di sessione siano Secure, HttpOnly e SameSite dopo un aggiornamento del framework.
