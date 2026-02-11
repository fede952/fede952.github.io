---
title: "Le 20 Domande più Frequenti sui Colloqui Docker e Risposte (Edizione 2026)"
description: "Supera il tuo colloquio per Senior DevOps con queste 20 domande avanzate su Docker che coprono container, immagini, networking, volumi, Docker Compose e best practice per la produzione."
date: 2026-02-11
tags: ["docker", "interview", "devops", "containers"]
keywords: ["domande colloquio docker", "colloquio senior devops", "domande containerizzazione", "risposte colloquio docker", "colloquio docker compose", "best practice dockerfile", "colloquio orchestrazione container", "domande networking docker", "colloquio ingegnere devops", "domande docker produzione"]
draft: false
schema_json: >
  {
    "@context": "https://schema.org",
    "@type": "TechArticle",
    "name": "Le 20 Domande più Frequenti sui Colloqui Docker e Risposte (Edizione 2026)",
    "description": "Domande avanzate per colloqui Docker per ruoli Senior DevOps che coprono container, immagini, networking e best practice per la produzione.",
    "proficiencyLevel": "Advanced",
    "inLanguage": "it"
  }
---

## Inizializzazione del Sistema

Docker è diventato una competenza imprescindibile per qualsiasi ruolo DevOps, SRE o di ingegneria backend. I selezionatori a livello senior si aspettano che tu vada oltre `docker run` — vogliono vedere che comprendi la stratificazione delle immagini, gli aspetti interni del networking, il rafforzamento della sicurezza e i pattern di orchestrazione per la produzione. Questa guida contiene le 20 domande più frequenti nei colloqui di livello Senior e Lead, con risposte dettagliate che dimostrano profondità.

**Hai bisogno di un rapido ripasso dei comandi prima del colloquio?** Salva nei preferiti il nostro [Cheatsheet Docker Captain's Log](/cheatsheets/docker-container-commands/).

---

## Concetti Fondamentali

<details>
<summary><strong>1. Qual è la differenza tra un container e una macchina virtuale?</strong></summary>
<br>

Una **macchina virtuale** esegue un sistema operativo guest completo su un hypervisor, incluso il proprio kernel, driver e librerie di sistema. Ogni VM è completamente isolata ma consuma risorse significative (GB di RAM, minuti per l'avvio).

Un **container** condivide il kernel del sistema operativo host e isola i processi utilizzando i namespace Linux e i cgroup. Include solo l'applicazione e le sue dipendenze — nessun kernel separato. Questo rende i container leggeri (MB), veloci da avviare (millisecondi) e altamente portabili.

Differenza chiave: le VM virtualizzano l'**hardware**, i container virtualizzano il **sistema operativo**.
</details>

<details>
<summary><strong>2. Cosa sono i layer delle immagini Docker e come funzionano?</strong></summary>
<br>

Un'immagine Docker è costruita da una serie di **layer di sola lettura**. Ogni istruzione nel Dockerfile (`FROM`, `RUN`, `COPY`, ecc.) crea un nuovo layer. I layer sono impilati uno sull'altro usando un filesystem union (come OverlayFS).

Quando un container viene eseguito, Docker aggiunge un sottile **layer scrivibile** in cima (il layer del container). Le modifiche fatte a runtime influenzano solo questo layer scrivibile — i layer sottostanti dell'immagine rimangono invariati.

Questa architettura consente:
- **Caching**: Se un layer non è cambiato, Docker lo riutilizza dalla cache durante le build.
- **Condivisione**: Più container dalla stessa immagine condividono i layer di sola lettura, risparmiando spazio su disco.
- **Efficienza**: Solo i layer modificati devono essere scaricati o inviati ai registry.
</details>

<details>
<summary><strong>3. Qual è la differenza tra CMD e ENTRYPOINT in un Dockerfile?</strong></summary>
<br>

Entrambi definiscono cosa viene eseguito quando un container si avvia, ma si comportano diversamente:

- **CMD** fornisce argomenti predefiniti che possono essere completamente sovrascritti a runtime. Se esegui `docker run myimage /bin/bash`, il CMD viene sostituito.
- **ENTRYPOINT** definisce l'eseguibile principale che viene sempre eseguito. Gli argomenti a runtime vengono aggiunti ad esso, non sostituiti.

Best practice: Usa `ENTRYPOINT` per il processo principale e `CMD` per gli argomenti predefiniti:

```dockerfile
ENTRYPOINT ["python", "app.py"]
CMD ["--port", "8080"]
```

Eseguendo `docker run myimage --port 3000` verrà eseguito `python app.py --port 3000`.
</details>

<details>
<summary><strong>4. Cos'è una build multi-stage e perché è importante?</strong></summary>
<br>

Una build multi-stage utilizza più istruzioni `FROM` in un singolo Dockerfile. Ogni `FROM` inizia una nuova fase di build, e puoi copiare selettivamente gli artefatti da una fase all'altra.

```dockerfile
# Stage 1: Build
FROM golang:1.21 AS builder
WORKDIR /app
COPY . .
RUN go build -o myapp

# Stage 2: Run (minimal image)
FROM alpine:3.18
COPY --from=builder /app/myapp /usr/local/bin/
CMD ["myapp"]
```

Questo produce un'immagine finale contenente solo il binario compilato — nessun tool di build, nessun codice sorgente, nessun file intermedio. Il risultato è un'immagine drasticamente più piccola (spesso 10-100 volte più piccola) con una superficie di attacco ridotta.
</details>

<details>
<summary><strong>5. Qual è la differenza tra COPY e ADD in un Dockerfile?</strong></summary>
<br>

Entrambi copiano file dal contesto di build nell'immagine, ma `ADD` ha funzionalità extra:
- `ADD` può estrarre automaticamente archivi `.tar` locali.
- `ADD` può scaricare file da URL.

Tuttavia, le best practice Docker raccomandano di usare `COPY` in quasi tutti i casi perché è esplicito e prevedibile. Usa `ADD` solo quando hai specificamente bisogno dell'estrazione tar. Non usare mai `ADD` per scaricare file — usa `RUN curl` o `RUN wget` invece, così il layer di download può essere cachato correttamente.
</details>

## Networking

<details>
<summary><strong>6. Spiega le modalità di rete di Docker (bridge, host, none, overlay).</strong></summary>
<br>

- **Bridge** (predefinito): Crea una rete interna privata sull'host. I container sullo stesso bridge possono comunicare tramite IP o nome del container. Il traffico verso l'esterno richiede il port mapping (`-p`).
- **Host**: Rimuove l'isolamento di rete. Il container condivide direttamente lo stack di rete dell'host. Nessun port mapping necessario, ma nessun isolamento. Utile per applicazioni con requisiti critici di prestazioni.
- **None**: Nessuna rete. Il container ha solo un'interfaccia loopback. Usato per job batch o carichi di lavoro sensibili alla sicurezza.
- **Overlay**: Si estende su più host Docker (usato in Swarm/Kubernetes). I container su macchine diverse possono comunicare come se fossero sulla stessa rete, utilizzando il tunneling VXLAN.
</details>

<details>
<summary><strong>7. Come funziona la comunicazione tra container?</strong></summary>
<br>

Su una rete bridge definita dall'utente, i container possono raggiungersi **tramite nome del container** attraverso il resolver DNS integrato di Docker. Il server DNS viene eseguito all'indirizzo `127.0.0.11` all'interno di ogni container.

Sulla rete bridge predefinita, la risoluzione DNS **non** è disponibile — i container possono comunicare solo tramite indirizzo IP, il che è inaffidabile poiché gli IP vengono assegnati dinamicamente.

Best practice: Crea sempre una rete bridge personalizzata (`docker network create mynet`) e collega i container ad essa. Non fare mai affidamento sul bridge predefinito per la comunicazione tra container.
</details>

<details>
<summary><strong>8. Qual è la differenza tra EXPOSE e la pubblicazione di una porta?</strong></summary>
<br>

`EXPOSE` in un Dockerfile è puramente **documentazione** — indica a chiunque legga il Dockerfile che l'applicazione ascolta su una porta specifica. NON apre o mappa effettivamente la porta.

La pubblicazione di una porta (`-p 8080:80`) crea effettivamente una regola di rete che mappa una porta dell'host a una porta del container, rendendo il servizio accessibile dall'esterno del container.

Puoi pubblicare porte che non sono nella direttiva `EXPOSE`, e `EXPOSE` da solo non fa nulla senza `-p`.
</details>

## Volumi e Storage

<details>
<summary><strong>9. Quali sono i tre tipi di mount Docker?</strong></summary>
<br>

1. **Volumi** (`docker volume create`): Gestiti da Docker, memorizzati in `/var/lib/docker/volumes/`. Ideali per dati persistenti (database). Sopravvivono alla rimozione del container. Portabili tra host.
2. **Bind mount** (`-v /host/path:/container/path`): Mappano una directory specifica dell'host nel container. Il percorso dell'host deve esistere. Ideali per lo sviluppo (ricaricamento live del codice). Non portabili.
3. **Mount tmpfs** (`--tmpfs /tmp`): Memorizzati solo nella memoria dell'host. Non vengono mai scritti su disco. Ideali per dati sensibili che non devono persistere (segreti, token di sessione).
</details>

<details>
<summary><strong>10. Come si persistono i dati da un container di database?</strong></summary>
<br>

Usa un **volume nominato** montato nella directory dei dati del database:

```bash
docker volume create pgdata
docker run -d -v pgdata:/var/lib/postgresql/data postgres:16
```

I dati sopravvivono ai riavvii e alle rimozioni del container. Quando aggiorni la versione del database, ferma il vecchio container, avviane uno nuovo con lo stesso volume e lascia che la nuova versione gestisca la migrazione dei dati.

Non usare mai i bind mount per database in produzione — i volumi hanno prestazioni I/O migliori e sono gestiti dal driver di storage di Docker.
</details>

## Sicurezza

<details>
<summary><strong>11. Come si protegge un container Docker in produzione?</strong></summary>
<br>

Pratiche chiave di hardening:
- **Esegui come non-root**: Usa la direttiva `USER` nel Dockerfile. Non eseguire mai processi applicativi come root.
- **Usa immagini base minimali**: `alpine`, `distroless` o `scratch` invece di `ubuntu`.
- **Rimuovi le capability**: Usa `--cap-drop ALL --cap-add <solo-necessarie>`.
- **Filesystem in sola lettura**: Usa `--read-only` e monta solo percorsi specifici scrivibili.
- **Nessun nuovo privilegio**: Usa `--security-opt=no-new-privileges`.
- **Scansiona le immagini**: Usa `docker scout`, Trivy o Snyk per rilevare vulnerabilità nelle immagini base e nelle dipendenze.
- **Firma le immagini**: Usa Docker Content Trust (`DOCKER_CONTENT_TRUST=1`) per verificare l'autenticità delle immagini.
- **Limita le risorse**: Usa `--memory`, `--cpus` per prevenire l'esaurimento delle risorse.
</details>

<details>
<summary><strong>12. Cos'è la modalità rootless di Docker?</strong></summary>
<br>

La modalità rootless di Docker esegue il daemon Docker e i container interamente all'interno di un namespace utente, senza richiedere privilegi root sull'host. Questo elimina la principale preoccupazione di sicurezza con Docker: che il daemon viene eseguito come root e un'evasione dal container significa accesso root all'host.

In modalità rootless, anche se un attaccante evade dal container, ottiene solo i privilegi dell'utente non privilegiato che esegue Docker. Il compromesso è che alcune funzionalità (come il binding a porte sotto la 1024) richiedono configurazione aggiuntiva.
</details>

## Docker Compose e Orchestrazione

<details>
<summary><strong>13. Qual è la differenza tra docker-compose up e docker-compose run?</strong></summary>
<br>

- `docker compose up`: Avvia **tutti** i servizi definiti in `docker-compose.yml`, crea reti/volumi e rispetta l'ordine `depends_on`. Tipicamente usato per avviare l'intero stack.
- `docker compose run <servizio> <comando>`: Avvia un **singolo** servizio con un comando una tantum. Non avvia i servizi dipendenti per impostazione predefinita (usa `--service-ports` per mappare le porte, `--rm` per la pulizia). Usato per eseguire migrazioni, test o attività di amministrazione.
</details>

<details>
<summary><strong>14. Come funziona depends_on e quali sono i suoi limiti?</strong></summary>
<br>

`depends_on` controlla l'**ordine di avvio** — assicura che il servizio A parta prima del servizio B. Tuttavia, aspetta solo che il container si **avvii**, non che l'applicazione al suo interno sia **pronta**.

Ad esempio, un container di database potrebbe avviarsi in secondi, ma PostgreSQL ha bisogno di tempo aggiuntivo per l'inizializzazione. Il container della tua app si avvierà e fallirà immediatamente nel tentativo di connessione.

Soluzione: Usa `depends_on` con una `condition` e un health check:

```yaml
services:
  db:
    image: postgres:16
    healthcheck:
      test: ["CMD-SHELL", "pg_isready -U user"]
      interval: 5s
      timeout: 5s
      retries: 5
  app:
    depends_on:
      db:
        condition: service_healthy
```
</details>

<details>
<summary><strong>15. Quando sceglieresti Docker Swarm rispetto a Kubernetes?</strong></summary>
<br>

**Docker Swarm**: Integrato in Docker, nessuna configurazione aggiuntiva. Ideale per deployment piccoli e medi dove la semplicità conta. Usa gli stessi file Docker Compose. Ecosistema e community limitati rispetto a Kubernetes. Adatto per team che non hanno ingegneri di piattaforma dedicati.

**Kubernetes**: Standard industriale per l'orchestrazione di container su larga scala. Supporta auto-scaling, aggiornamenti rolling, service mesh, custom resource definition e un ecosistema vasto (Helm, Istio, ArgoCD). Complessità e curva di apprendimento più elevate. Necessario per deployment su larga scala, multi-team e multi-cloud.

Regola pratica: Se hai meno di 20 servizi e un team piccolo, Swarm è sufficiente. Oltre a ciò, Kubernetes vale l'investimento.
</details>

## Produzione e Risoluzione dei Problemi

<details>
<summary><strong>16. Come si riduce la dimensione di un'immagine Docker?</strong></summary>
<br>

1. **Usa build multi-stage** — tieni i tool di build fuori dall'immagine finale.
2. **Usa immagini base minimali** — `alpine` (~5MB) invece di `ubuntu` (~75MB).
3. **Combina i comandi RUN** — ogni `RUN` crea un layer. Concatena i comandi con `&&` e pulisci nello stesso layer.
4. **Usa .dockerignore** — escludi `node_modules`, `.git`, file di test, documentazione dal contesto di build.
5. **Ordina i layer per frequenza di modifica** — metti i layer che cambiano raramente (dipendenze) prima dei layer che cambiano frequentemente (codice sorgente) per massimizzare i cache hit.
</details>

<details>
<summary><strong>17. Un container continua a riavviarsi. Come fai il debug?</strong></summary>
<br>

Approccio passo dopo passo:
1. `docker ps -a` — controlla il codice di uscita. Codice 137 = terminato per OOM. Codice 1 = errore dell'applicazione.
2. `docker logs <container>` — leggi i log dell'applicazione per stack trace o messaggi di errore.
3. `docker inspect <container>` — controlla `State.OOMKilled`, limiti delle risorse e variabili d'ambiente.
4. `docker run -it --entrypoint /bin/sh <image>` — avvia una shell interattiva per fare debug dell'ambiente manualmente.
5. `docker stats` — controlla se il container sta raggiungendo i limiti di memoria o CPU.
6. Controlla `docker events` — cerca segnali di kill o eventi OOM dal daemon.
</details>

<details>
<summary><strong>18. Qual è la differenza tra docker stop e docker kill?</strong></summary>
<br>

- `docker stop` invia **SIGTERM** al processo principale (PID 1) e attende un periodo di grazia (predefinito 10 secondi). Se il processo non termina, Docker invia SIGKILL. Questo permette all'applicazione di eseguire uno shutdown graduale (chiudere connessioni, svuotare buffer, salvare stato).
- `docker kill` invia **SIGKILL** immediatamente. Il processo viene terminato senza alcuna possibilità di pulizia. Usa solo quando un container non risponde.

Best practice: Usa sempre `docker stop` in produzione. Assicurati che la tua applicazione gestisca correttamente SIGTERM.
</details>

<details>
<summary><strong>19. Come si gestiscono i segreti in Docker?</strong></summary>
<br>

**Mai** incorporare segreti nelle immagini (ENV nel Dockerfile, COPY di file .env). Persistono nei layer dell'immagine e sono visibili con `docker history`.

Approcci per livello di maturità:
- **Base**: Passa i segreti tramite `--env-file` a runtime (file non incluso nell'immagine).
- **Meglio**: Usa i secrets di Docker Swarm o Kubernetes secrets (montati come file, non come variabili d'ambiente).
- **Ottimale**: Usa un gestore di segreti esterno (HashiCorp Vault, AWS Secrets Manager, Azure Key Vault) e inietta i segreti a runtime tramite sidecar o init container.
</details>

<details>
<summary><strong>20. Cos'è un health check Docker e perché è fondamentale?</strong></summary>
<br>

Un health check è un comando che Docker esegue periodicamente all'interno del container per verificare che l'applicazione funzioni effettivamente — non solo che il processo sia in esecuzione.

```dockerfile
HEALTHCHECK --interval=30s --timeout=5s --retries=3 \
  CMD curl -f http://localhost:3000/health || exit 1
```

Senza un health check, Docker sa solo se il processo è vivo (il PID esiste). Con un health check, Docker sa se l'applicazione è **sana** (risponde alle richieste). Questo è fondamentale per:
- **Bilanciatori di carico**: Instradare il traffico solo verso container sani.
- **Orchestratori**: Riavviare automaticamente i container non sani.
- **depends_on**: Attendere la prontezza effettiva, non solo l'avvio del processo.
</details>
