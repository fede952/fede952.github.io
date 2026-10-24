---
title: "Generatore Cron: Crea e Spiega Espressioni"
description: "Crea espressioni cron in modo visuale, traducile in linguaggio semplice e vedi le prossime 5 esecuzioni. Generatore crontab gratuito per Linux e CI."
intro: "**EasyCron** costruisce un'espressione cron a clic, traduce in linguaggio semplice quella che hai già ed elenca le sue prossime cinque esecuzioni. Copre la sintassi standard crontab a cinque campi usata da cron su Linux, dai CronJob di Kubernetes e dalla maggior parte degli scheduler CI."
date: 2026-02-03
lastmod: 2026-10-24
reviewed: false
keywords: ["generatore cron", "espressione cron", "crontab generator", "cron ogni 5 minuti", "esempi crontab", "spiegare espressione cron", "pianificare job cron", "prossima esecuzione cron"]
tags: ["linux", "devops", "cron", "strumento"]
app_category: "DeveloperApplication"
tool_file: "/tools/easy-cron/"
tool_title: "EasyCron, generatore di espressioni cron"
tool_height: 1100
tool_sandbox: "allow-scripts allow-same-origin"
tool_allow: "clipboard-write"
howto:
  - "Parti da un **preset** (ogni 5 minuti, giorni feriali alle 9, mensile il giorno 1…) o dal predefinito `* * * * *`."
  - "Usa le schede **Minute, Hour, Day, Month, Weekday** per impostare ogni campo: tutti i valori, un intervallo come ogni 15 minuti o valori specifici scelti su una griglia. I pulsanti rapidi coprono scelte comuni come orario d'ufficio o giorni feriali."
  - "Guarda l'espressione, la sua descrizione e le **Next 5 runs** aggiornarsi a ogni clic."
  - "Premi **Copy** e incolla l'espressione nel crontab, nel manifest del CronJob o nel file della CI."
  - "Per capire una pianificazione esistente, incollala nel **Reverse Translator** e premi **Parse**: ottieni descrizione e prossime esecuzioni, e il builder la carica per modificarla."
faq:
  - q: "Cosa significano i cinque campi di un'espressione cron?"
    a: "Nell'ordine: minuto (0–59), ora (0–23), giorno del mese (1–31), mese (1–12) e giorno della settimana (0–6, domenica = 0). `30 2 * * 1` significa quindi alle 02:30 di ogni lunedì. Un asterisco vuol dire \"qualsiasi valore\" per quel campo."
  - q: "Come eseguo un job cron ogni 5 minuti?"
    a: "`*/5 * * * *`. Il `*/5` nel campo dei minuti significa ogni quinto minuto partendo da 0: 00, 05, 10 … 55. Allo stesso modo `0 */2 * * *` gira all'inizio di ogni seconda ora e `*/15 9-17 * * 1-5` ogni 15 minuti in orario d'ufficio nei giorni feriali."
  - q: "Cosa succede se imposto sia il giorno del mese sia il giorno della settimana?"
    a: "Il cron standard (Vixie) esegue il job quando corrisponde *uno dei due*, non quando corrispondono entrambi. `0 9 1 * 1` gira alle 09:00 il giorno 1 di ogni mese *e* ogni lunedì. Il calcolo delle prossime esecuzioni di EasyCron segue la stessa regola, che sorprende molti."
  - q: "In che fuso orario sono le prossime esecuzioni?"
    a: "Nel fuso orario del tuo browser. Un demone cron usa quello della macchina su cui gira, spesso UTC su server e container. I CronJob di Kubernetes usano il fuso del controller, a meno di impostare `spec.timeZone`. Se il tuo server è in UTC, converti prima di fidarti dell'elenco."
  - q: "EasyCron supporta i secondi, nomi come MON o JAN, o @daily?"
    a: "No. È pensato per la sintassi portabile a cinque campi: numeri, `*`, intervalli come `1-5`, liste come `1,15`, passi come `*/10` e intervalli con passo come `0-30/10`. Secondi in stile Quartz e `L`, `W`, `#`, `?` non sono supportati. Scrivi `0 0 * * *` al posto di `@daily` e usa `0` (non `7`) per la domenica."
  - q: "Viene inviato qualcosa a un server?"
    a: "No. Builder, descrizione e calcolo delle esecuzioni sono JavaScript in questa pagina. L'unica cosa salvata è la preferenza per il tema chiaro o scuro, nel localStorage del browser."
---

## Come funziona

### Costruire l'espressione

Ognuno dei cinque campi ha il suo stato: **every** (`*`), **interval** (`*/n`, con scelte sensate per campo come 5, 10, 15 o 30 minuti e 2, 3, 4, 6, 8 o 12 ore) oppure valori **specifici** scelti su una griglia. In modalità specifica i numeri selezionati vengono ordinati e uniti da virgole (`0,15,30,45`). Se sono selezionati tutti i valori possibili, il campo torna a `*`. Le cinque parti vengono unite da spazi nell'espressione finale.

### Interpretare e spiegare

Il traduttore inverso divide l'espressione sugli spazi e richiede esattamente cinque campi. Ogni campo viene espanso nell'insieme dei valori che corrispondono:

| Sintassi | Esempio | Si espande in |
|---|---|---|
| `*` | `*` nelle ore | 0, 1, 2 … 23 |
| `*/n` | `*/15` nei minuti | 0, 15, 30, 45 |
| `a-b` | `1-5` nei giorni della settimana | lun … ven |
| `a-b/n` | `0-30/10` nei minuti | 0, 10, 20, 30 |
| lista | `1,15` nei giorni | 1 e 15 |

La descrizione (in inglese) viene composta con regole che suonano come le direbbe una persona: `*/5 * * * *` diventa "Every 5 minutes", `0 9 * * 1-5` diventa "At 09:00, Monday through Friday", `0 0 1 1 *` diventa "At 00:00, on day 1 of the month, in January".

### Calcolare le prossime esecuzioni

Partendo da un minuto da adesso, il calcolatore avanza nel tempo saltando intere unità che non possono corrispondere: un mese fuori dall'insieme salta al giorno 1 del mese successivo, un giorno che non corrisponde salta alla mezzanotte del giorno dopo, un'ora che non corrisponde all'ora successiva. Quando mese, giorno, ora e minuto corrispondono tutti, l'orario viene registrato, finché non trova cinque esecuzioni o ha cercato per quattro anni. Per questo le pianificazioni impossibili come `0 0 31 2 *` (31 febbraio) segnalano che non esiste alcuna esecuzione futura.

Il controllo del giorno segue la vera semantica di cron: se solo uno dei due campi del giorno è ristretto, decide quello; se lo sono entrambi, basta che corrisponda uno dei due.

## Casi d'uso

- **Scrivere una riga di crontab** per backup, rotazione dei log, rinnovo dei certificati o uno script di pulizia senza dover ricontrollare l'ordine dei campi.
- **CronJob di Kubernetes e pipeline CI.** `schedule:` di GitHub Actions, le pianificazioni delle pipeline GitLab e `spec.schedule` di Kubernetes usano gli stessi cinque campi.
- **Rivedere la pianificazione di qualcun altro.** Incolla il criptico `15 3 */2 * *` da una configurazione e leggi "At 03:15, every 2nd day of the month".
- **Intercettare errori prima della produzione**, come un job pensato per "giorni feriali alle 9" che gira anche il primo del mese perché sono stati impostati entrambi i campi del giorno.
- **Pianificare finestre di manutenzione.** Controlla quando cadono esattamente le prossime cinque esecuzioni, poi adatta al fuso orario del server.
