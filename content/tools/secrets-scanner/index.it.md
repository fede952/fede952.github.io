---
title: "Secrets Scanner: Trova API Key nel Codice"
description: "Incolla un .env, un file di configurazione o del codice e trova API key, token, chiavi private e password esposte prima del commit. Tutto in locale."
intro: "**SafeEnv** analizza il testo alla ricerca di credenziali esposte: chiavi AWS, GitHub, Stripe, OpenAI e Slack, blocchi di chiavi private, password nelle stringhe di connessione e valori ad alta entropia accanto a nomi come `SECRET` o `TOKEN`. Incolla o trascina un file: la scansione avviene interamente nel tuo browser."
date: 2026-07-05
lastmod: 2026-10-24
reviewed: false
keywords: ["secrets scanner", "trovare api key nel codice", "scanner file env", "password hardcoded", "rilevare credenziali esposte", "leak token github", "scansione segreti online", "api key esposta"]
tags: ["sicurezza", "devsecops", "segreti", "strumento"]
app_category: "DeveloperApplication"
tool_file: "/tools/secrets-scanner/"
tool_title: "SafeEnv, scanner di segreti"
tool_height: 1000
tool_sandbox: "allow-scripts allow-same-origin"
tool_allow: "clipboard-write"
howto:
  - "Incolla nella casella il contenuto di un `.env`, `docker-compose.yml`, configurazione CI, file Terraform o frammento di codice, oppure usa **Scan a file…** o trascinaci sopra un file."
  - "Premi **Scan for secrets**. Un file di configurazione tipico viene analizzato in pochi millisecondi."
  - "Leggi i chip di riepilogo (critical, high, medium, low, info) e l'elenco dei risultati, ordinati per gravità e poi per numero di riga."
  - "Ogni risultato mostra la regola che ha trovato la corrispondenza, la riga, il valore mascherato (solo i primi e gli ultimi quattro caratteri) e cosa fare."
  - "Risolvi prima i critici: ruota la credenziale, toglila dal file e dalla cronologia git e caricala da un secret manager o da una variabile d'ambiente. **Copy report** ti dà un riepilogo testuale da allegare a un ticket."
faq:
  - q: "È sicuro incollare segreti reali in questo scanner?"
    a: "Lo scanner è JavaScript che gira in questa pagina e non fa richieste di rete con il tuo testo, quindi nulla arriva ai nostri server. A schermo compaiono valori mascherati, mai i segreti completi. Detto questo, se trovi una chiave di produzione reale, considerala già compromessa e ruotala."
  - q: "Che tipi di segreti rileva?"
    a: "Venti formati specifici, tra cui access key ID e secret key AWS, token GitHub e GitLab, chiavi Stripe live e di test, API key Google, API key OpenAI e Anthropic, token e webhook Slack, chiavi SendGrid, npm, PyPI, bot Telegram e Twilio, JSON Web Token, blocchi di chiavi private e credenziali dentro URL di database o HTTP. Un secondo passaggio segnala valori ad alta entropia e password hardcoded in qualsiasi riga `CHIAVE=VALORE`."
  - q: "Perché un valore viene segnalato come \"high entropy\"?"
    a: "Le stringhe dall'aspetto casuale sono proprio come appaiono i segreti generati. Lo scanner calcola l'entropia di Shannon di ogni valore lungo almeno 20 caratteri e lo segnala da 4,3 bit per carattere in su. I valori accanto a nomi che contengono secret, token, password, key o auth ricevono una gravità maggiore. Anche hash, UUID e ID di build possono farlo scattare, quindi guarda il contesto."
  - q: "Cosa faccio se un segreto è finito in un commit git?"
    a: "Cancellare la riga con un nuovo commit non basta: il segreto resta nella cronologia e in ogni clone. Prima ruota o revoca la credenziale, poi riscrivi la cronologia con `git filter-repo` o BFG Repo-Cleaner, fai un force-push e chiedi ai collaboratori di clonare di nuovo. La rotazione è il passo che ti protegge davvero."
  - q: "Sostituisce strumenti come Gitleaks o il secret scanning di GitHub?"
    a: "No, li completa. Usa un hook pre-commit o uno scanner in CI per ogni commit e la push protection di GitHub sui tuoi repository. SafeEnv serve nei momenti intermedi: controllare un frammento prima di incollarlo in una chat, in un ticket o in un assistente AI, o rivedere una configurazione che qualcuno ti ha mandato."
  - q: "Perché i valori segnaposto sono elencati come info?"
    a: "Righe come `API_KEY=your-api-key-here` o `PASSWORD=${DB_PASSWORD}` hanno la forma di un segreto ma sono modelli. Lo scanner riconosce gli schemi di segnaposto più comuni (your-, changeme, example, xxx, `${VAR}`, `<value>`) e li riporta come info, così puoi confermare che siano voluti."
---

## Come funziona

Lo scanner è un piccolo motore di regole senza dipendenze, che fa due passaggi sul testo.

### Passaggio 1: formati di token noti

Venti espressioni regolari riconoscono formati che i fornitori documentano pubblicamente, soprattutto tramite prefisso fisso e lunghezza. Alcuni esempi di ciò che cercano le regole:

| Regola | Firma riconosciuta | Gravità |
|---|---|---|
| Blocco di chiave privata | `-----BEGIN … PRIVATE KEY-----` (RSA, EC, DSA, OpenSSH, PGP, cifrata) | Critica |
| Access key ID AWS | `AKIA`, `ASIA`, `ABIA` o `ACCA` seguiti da 16 lettere maiuscole o cifre | Critica |
| Secret access key AWS | Un valore Base64 di 40 caratteri assegnato a un nome come `aws_secret_access_key` | Critica |
| Token GitHub | Prefissi `ghp_`, `gho_`, `ghu_`, `ghs_`, `ghr_` o `github_pat_` | Critica |
| Chiave Stripe live | Prefissi `sk_live_` / `rk_live_` | Critica |
| Chiave OpenAI / Anthropic | Prefissi `sk-proj-`, `sk-svcacct-`, `sk-ant-` | Critica |
| API key Google | `AIza` seguito da 35 caratteri | Alta |
| Token / webhook Slack | Token `xox[baprs]-`, URL `hooks.slack.com/services/…` | Alta |
| Credenziali in un URI | `postgres://utente:password@host`, anche MySQL, MongoDB, Redis, AMQP, FTP e basic auth HTTP | Alta |
| JSON Web Token | Tre segmenti Base64URL che iniziano con `eyJ` | Media |
| Chiave Stripe di test / pubblicabile | `sk_test_`, `pk_live_`, `pk_test_` | Bassa |

Per ogni corrispondenza vengono registrati il numero di riga (contando gli a capo che la precedono) e una versione **mascherata** del valore, che conserva solo i primi e gli ultimi quattro caratteri: il report stesso non contiene mai il segreto.

### Passaggio 2: analisi generica `CHIAVE=VALORE`

Le righe non già intercettate da una regola specifica vengono lette come assegnazioni, la sintassi di `.env`, YAML e della maggior parte dei formati di configurazione (prefissi `export`, virgolette e commenti `#` finali sono gestiti). Per ogni valore di almeno sei caratteri:

1. Se sembra un **segnaposto** (`your-…`, `changeme`, `example`, `xxxx`, `${VAR}`, `<value>`, `true/false/null`), viene riportato come *info* quando il nome della chiave sembra un segreto, altrimenti ignorato.
2. I valori che contengono un URL o spazi vengono saltati, perché raramente sono segreti di per sé.
3. Viene calcolata l'**entropia di Shannon** H = −Σ p·log₂(p) sulle frequenze dei caratteri. Un valore di 20+ caratteri con H ≥ 4,3 bit per carattere viene segnalato come *high entropy*, con gravità alta se il nome della chiave contiene secret, token, passw, pwd, api_key, private, credential o auth, media altrimenti.
4. Un valore a entropia più bassa assegnato a un nome tipo password viene riportato come *hardcoded password*.

I risultati sono ordinati per gravità, poi per riga. Non viene salvato nulla: svuota la casella o chiudi la scheda e il testo sparisce.

### Limiti

La scansione con regex trova *formati*, non *validità*: non può dire se una chiave è ancora attiva. Non vede nemmeno segreti spezzati su più righe, cifrati o codificati in modi insoliti. Per questo è un controllo rapido, non un sostituto della scansione nella pipeline CI.

## Casi d'uso

- **Prima di condividere un frammento.** Controlla una configurazione o uno stack trace prima di incollarlo su Slack, in una issue GitHub, su Stack Overflow o in un chatbot AI.
- **Prima del primo commit.** Analizza `.env.example`, `docker-compose.yml` e file CI di un nuovo progetto per essere sicuro che non sia scappato un valore reale.
- **Revisione di una pull request o di un passaggio di consegne.** Incolla il diff dei file di configurazione e cerca qualsiasi elemento critico.
- **Risposta agli incidenti.** Dopo una sospetta fuga di dati, analizza log o configurazioni esportati per elencare tutte le credenziali da ruotare.
- **Insegnare buone abitudini.** Il file di esempio mostra a un team, in pochi secondi, quanti segreti contiene un normale `.env`.
