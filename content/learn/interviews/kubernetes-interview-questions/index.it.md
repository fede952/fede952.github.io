---
title: "Kubernetes (K8s) Preparazione al Colloquio: Domande e Risposte Livello Senior"
description: "20 domande avanzate su Kubernetes per colloqui DevOps e SRE Senior. Copre architettura, ciclo di vita dei pod, networking, storage, RBAC e troubleshooting in produzione."
date: 2026-02-11
tags: ["kubernetes", "interview", "devops", "cloud-native"]
keywords: ["k8s interview questions", "cka exam prep", "kubernetes architecture questions", "kubernetes interview answers", "pod lifecycle interview", "kubernetes networking questions", "kubernetes rbac", "senior sre interview", "kubernetes troubleshooting", "helm interview questions"]
draft: false
schema_json: >
  {
    "@context": "https://schema.org",
    "@type": "TechArticle",
    "name": "Kubernetes (K8s) Preparazione al Colloquio: Domande e Risposte Livello Senior",
    "description": "20 domande avanzate su Kubernetes su architettura, networking, storage, sicurezza e troubleshooting in produzione.",
    "proficiencyLevel": "Advanced",
    "inLanguage": "it"
  }
---

## Inizializzazione del Sistema

Kubernetes è il sistema operativo del cloud — e la competenza più richiesta per ruoli DevOps, SRE e Platform Engineering. I colloqui di livello senior vanno in profondità: ti verranno poste domande sugli interni del control plane, modelli di networking, RBAC, gestione delle risorse e come debuggare incidenti in produzione sotto pressione. Questa guida contiene 20 domande che appaiono ripetutamente nei colloqui delle principali aziende tech, con risposte che dimostrano la profondità attesa a livello Staff/Senior.

**Hai bisogno di un rapido ripasso dei comandi?** Tieni aperto il nostro [Kubernetes Kubectl Cheat Sheet](/cheatsheets/kubernetes-kubectl-cheat-sheet/) durante la preparazione.

---

## Architettura

<details>
<summary><strong>1. Descrivi i componenti del control plane di Kubernetes e le loro responsabilità.</strong></summary>
<br>

Il control plane gestisce lo stato del cluster:

- **kube-apiserver**: La porta d'ingresso al cluster. Ogni comando `kubectl`, azione dei controller e decisione dello scheduler passa attraverso l'API server. Valida e persiste lo stato su etcd.
- **etcd**: Un archivio chiave-valore distribuito che contiene l'intero stato del cluster (stato desiderato, stato attuale, configurazioni, secret). È l'unica fonte di verità.
- **kube-scheduler**: Monitora i pod appena creati senza un nodo assegnato e seleziona un nodo in base ai requisiti di risorse, regole di affinità, taint e vincoli.
- **kube-controller-manager**: Esegue cicli di controller (controller Deployment, ReplicaSet, Node, Job) che riconciliano continuamente lo stato desiderato con lo stato attuale.
- **cloud-controller-manager**: Si integra con le API del cloud provider per LoadBalancer, provisioning dello storage e ciclo di vita dei nodi.
</details>

<details>
<summary><strong>2. Cosa succede quando esegui `kubectl apply -f deployment.yaml`?</strong></summary>
<br>

1. `kubectl` invia un HTTP POST/PATCH all'**API server** con il manifest del Deployment.
2. L'API server **valida** la richiesta (autenticazione, autorizzazione tramite RBAC, admission controller).
3. L'API server scrive l'oggetto Deployment su **etcd**.
4. Il **controller Deployment** rileva il nuovo Deployment e crea un **ReplicaSet**.
5. Il **controller ReplicaSet** lo rileva e crea il numero specificato di oggetti **Pod**.
6. Lo **scheduler** rileva i pod non schedulati e assegna ciascuno a un nodo in base alla disponibilità di risorse e ai vincoli.
7. Il **kubelet** su ogni nodo assegnato rileva l'assegnazione del pod, scarica l'immagine del container e avvia il container tramite il runtime del container (containerd/CRI-O).
8. Il **kube-proxy** su ogni nodo aggiorna le regole iptables/IPVS se è associato un Service.
</details>

<details>
<summary><strong>3. Qual è la differenza tra Deployment, StatefulSet e DaemonSet?</strong></summary>
<br>

- **Deployment**: Gestisce applicazioni stateless. I pod sono intercambiabili, possono essere scalati liberamente e vengono creati/distrutti in qualsiasi ordine. Ideale per web server, API, worker.
- **StatefulSet**: Gestisce applicazioni stateful. Ogni pod ottiene un **hostname stabile** (`pod-0`, `pod-1`), **storage persistente** (PVC per pod) e i pod vengono creati/distrutti in **ordine**. Ideale per database, Kafka, ZooKeeper.
- **DaemonSet**: Garantisce **un pod per nodo**. Quando un nuovo nodo si unisce al cluster, un pod viene automaticamente schedulato su di esso. Ideale per raccoglitori di log, agenti di monitoraggio, plugin di rete.
</details>

<details>
<summary><strong>4. Spiega il ciclo di vita del pod e le sue fasi.</strong></summary>
<br>

Un pod attraversa queste fasi:

1. **Pending**: Il pod è accettato ma non ancora schedulato o le immagini sono in fase di download.
2. **Running**: Almeno un container è in esecuzione o in fase di avvio/riavvio.
3. **Succeeded**: Tutti i container sono usciti con codice 0 (per Job/workload batch).
4. **Failed**: Tutti i container sono terminati, almeno uno è uscito con un codice diverso da zero.
5. **Unknown**: Il nodo è irraggiungibile, lo stato del pod non può essere determinato.

All'interno di un pod in esecuzione, i container possono trovarsi negli stati: **Waiting** (download immagine, init container), **Running**, o **Terminated** (uscito o crashato).
</details>

## Networking

<details>
<summary><strong>5. Spiega il modello di networking di Kubernetes.</strong></summary>
<br>

Il networking di Kubernetes segue tre regole fondamentali:

1. **Ogni pod ottiene il proprio indirizzo IP** — nessun NAT tra i pod.
2. **Tutti i pod possono comunicare con tutti gli altri pod** tra i nodi senza NAT.
3. **L'IP che un pod vede per sé stesso** è lo stesso IP che gli altri usano per raggiungerlo.

Questo è implementato dai plugin CNI (Container Network Interface) come Calico, Flannel, Cilium o Weave. Creano una rete overlay o underlay che soddisfa queste regole. Ogni nodo ottiene una sottorete CIDR per i pod e il plugin CNI gestisce il routing tra i nodi.
</details>

<details>
<summary><strong>6. Qual è la differenza tra i servizi ClusterIP, NodePort e LoadBalancer?</strong></summary>
<br>

- **ClusterIP** (predefinito): IP virtuale solo interno. Accessibile solo dall'interno del cluster. Usato per la comunicazione tra servizi.
- **NodePort**: Espone il servizio su una porta statica (30000-32767) sull'IP di ogni nodo. Il traffico esterno può raggiungere `<NodeIP>:<NodePort>`. Si basa su ClusterIP.
- **LoadBalancer**: Provisiona un load balancer esterno tramite il cloud provider. Ottiene un IP/DNS pubblico. Si basa su NodePort. Usato per servizi pubblici in produzione.

Esiste anche **ExternalName**, che mappa un servizio a un CNAME DNS (nessun proxying, solo risoluzione DNS).
</details>

<details>
<summary><strong>7. Cos'è un Ingress e come si differenzia da un Service?</strong></summary>
<br>

Un **Service** opera al Layer 4 (TCP/UDP) — instrada il traffico ai pod in base a IP e porta.

Un **Ingress** opera al Layer 7 (HTTP/HTTPS) — instrada il traffico in base a hostname e percorso URL. Un singolo Ingress può instradare `api.example.com` al servizio API e `app.example.com` al servizio frontend, tutto attraverso un unico load balancer.

Un Ingress richiede un **Ingress Controller** (nginx-ingress, Traefik, HAProxy, AWS ALB) per implementare effettivamente le regole di routing. La risorsa Ingress è solo una configurazione — il controller fa il lavoro.
</details>

<details>
<summary><strong>8. Come funziona il DNS all'interno di un cluster Kubernetes?</strong></summary>
<br>

Kubernetes esegue **CoreDNS** (o kube-dns) come add-on del cluster. Ogni servizio ottiene un record DNS:

- `<service-name>.<namespace>.svc.cluster.local` → ClusterIP
- `<pod-ip-dashed>.<namespace>.pod.cluster.local` → Pod IP

Quando un pod effettua una query DNS per `my-service`, il resolver in `/etc/resolv.conf` (configurato da kubelet) aggiunge i domini di ricerca e interroga CoreDNS. CoreDNS monitora l'API server per le modifiche a Service/Endpoint e aggiorna i suoi record automaticamente.
</details>

## Storage

<details>
<summary><strong>9. Spiega PersistentVolume (PV), PersistentVolumeClaim (PVC) e StorageClass.</strong></summary>
<br>

- **PersistentVolume (PV)**: Un pezzo di storage provisionato da un amministratore o dinamicamente da una StorageClass. Esiste indipendentemente da qualsiasi pod. Ha un ciclo di vita separato dai pod.
- **PersistentVolumeClaim (PVC)**: Una richiesta di storage da parte di un pod. Specifica dimensione, modalità di accesso e opzionalmente una StorageClass. Kubernetes associa il PVC a un PV corrispondente.
- **StorageClass**: Definisce una classe di storage (SSD, HDD, NFS) e il provisioner che crea PV dinamicamente. Permette il provisioning dello storage on-demand — nessun intervento dell'amministratore necessario.

Flusso: Pod referenzia PVC → PVC richiede storage dalla StorageClass → StorageClass attiva il provisioner → Provisioner crea PV → PVC si associa a PV → Pod monta PV.
</details>

<details>
<summary><strong>10. Cosa sono le modalità di accesso e le policy di recupero?</strong></summary>
<br>

**Modalità di Accesso**:
- **ReadWriteOnce (RWO)**: Montato in lettura/scrittura da un singolo nodo. Più comune (AWS EBS, GCE PD).
- **ReadOnlyMany (ROX)**: Montato in sola lettura da molti nodi. Usato per configurazioni condivise.
- **ReadWriteMany (RWX)**: Montato in lettura/scrittura da molti nodi. Richiede storage di rete (NFS, EFS, CephFS).

**Policy di Recupero** (cosa succede quando il PVC viene eliminato):
- **Retain**: Il PV viene mantenuto con i suoi dati. L'amministratore deve recuperarlo manualmente.
- **Delete**: PV e storage sottostante vengono eliminati. Predefinito per il provisioning dinamico.
- **Recycle** (deprecato): `rm -rf` basilare sul volume. Usa Retain o Delete al suo posto.
</details>

## Sicurezza e RBAC

<details>
<summary><strong>11. Come funziona RBAC in Kubernetes?</strong></summary>
<br>

RBAC (Role-Based Access Control) ha quattro oggetti:

- **Role**: Definisce i permessi (verbi: get, list, create, delete) sulle risorse (pod, servizi, secret) all'interno di un **singolo namespace**.
- **ClusterRole**: Come Role ma a **livello cluster** (tutti i namespace, o risorse con scope cluster come i nodi).
- **RoleBinding**: Associa un Role a un utente, gruppo o service account all'interno di un namespace.
- **ClusterRoleBinding**: Associa un ClusterRole a un soggetto in tutto il cluster.

Principio: Inizia con i permessi minimi necessari. Non associare mai `cluster-admin` ai service account delle applicazioni. Verifica RBAC regolarmente con `kubectl auth can-i`.
</details>

<details>
<summary><strong>12. Cosa sono i Pod Security Standards (PSS)?</strong></summary>
<br>

I Pod Security Standards hanno sostituito le PodSecurityPolicies (rimosse in K8s 1.25). Definiscono tre livelli di sicurezza:

- **Privileged**: Senza restrizioni. Permette tutto. Usato per pod a livello di sistema (plugin CNI, driver storage).
- **Baseline**: Previene escalation di privilegi note. Blocca hostNetwork, hostPID, container privilegiati, ma permette la maggior parte dei workload.
- **Restricted**: Sicurezza massima. Richiede non-root, rimozione di tutte le capability, filesystem root in sola lettura, nessuna escalation di privilegi.

Applicato tramite il controller **Pod Security Admission** a livello di namespace usando le label:
```yaml
metadata:
  labels:
    pod-security.kubernetes.io/enforce: restricted
```
</details>

<details>
<summary><strong>13. Come si gestiscono i secret in Kubernetes in modo sicuro?</strong></summary>
<br>

I secret predefiniti di Kubernetes sono **codificati in base64, non crittografati**. Chiunque con accesso alle API può decodificarli.

Passi per l'hardening:
1. **Abilitare la crittografia a riposo** in etcd (`EncryptionConfiguration` con AES-CBC o provider KMS).
2. **Usare gestori di secret esterni** (Vault, AWS Secrets Manager) con l'External Secrets Operator o il CSI Secrets Store Driver.
3. **RBAC**: Limitare `get`/`list` sui secret solo ai service account che ne hanno bisogno.
4. **Montare come file**, non come variabili d'ambiente — le variabili d'ambiente possono trapelare tramite log, dump dei crash e `/proc`.
5. **Ruotare i secret** regolarmente e usare credenziali a breve scadenza dove possibile.
</details>

## Scheduling e Risorse

<details>
<summary><strong>14. Spiega le request e i limit delle risorse.</strong></summary>
<br>

- **Request**: La quantità di CPU/memoria **garantita** al container. Lo scheduler usa le request per decidere quale nodo ha capacità sufficiente.
- **Limit**: La quantità **massima** che un container può usare. Se un container supera il suo limit di memoria, viene ucciso per OOM. Se supera il limit di CPU, viene rallentato.

Classi QoS basate su request/limit:
- **Guaranteed**: Request == Limit per tutti i container. Priorità più alta, ultimo ad essere evicted.
- **Burstable**: Request < Limit. Priorità media.
- **BestEffort**: Nessuna request o limit impostato. Primo ad essere evicted sotto pressione.

Best practice: Imposta sempre le request (per l'accuratezza dello scheduling) e i limit (per la stabilità del cluster).
</details>

<details>
<summary><strong>15. Cosa sono i taint, le toleration e la node affinity?</strong></summary>
<br>

- **Taint** sono applicati ai nodi: "Non schedulare pod qui a meno che non tollerino questo taint." Esempio: `kubectl taint nodes gpu-node gpu=true:NoSchedule`.
- **Toleration** sono applicati ai pod: "Posso tollerare questo taint." I pod con toleration corrispondenti possono essere schedulati su nodi con taint.
- **Node Affinity** è una spec del pod che dice "Preferisci o richiedi lo scheduling su nodi con label specifiche." Esempio: richiedere nodi con `disktype=ssd`.

Usali insieme: Applica taint ai nodi GPU → solo i pod con toleration GPU e affinità GPU ci finiranno. Previene che workload non-GPU sprechino hardware costoso.
</details>

## Troubleshooting

<details>
<summary><strong>16. Un pod è bloccato in CrashLoopBackOff. Come lo debugghi?</strong></summary>
<br>

`CrashLoopBackOff` significa che il container continua a crashare e Kubernetes sta aspettando prima di riavviarlo (ritardo esponenziale fino a 5 minuti).

Passi di debug:
1. `kubectl describe pod <name>` — controlla Events, Last State, Exit Code.
2. `kubectl logs <pod> --previous` — leggi i log dall'istanza crashata.
3. Analisi del codice di uscita: 1 = errore applicazione, 137 = OOM killed, 139 = segfault, 143 = SIGTERM.
4. Se il container crasha troppo velocemente per i log: `kubectl run debug --image=<image> --command -- sleep 3600` ed esegui exec per ispezionare l'ambiente.
5. Controlla se le probe di readiness/liveness sono mal configurate (probe che colpisce porta/path sbagliato).
6. Controlla i limit delle risorse — il container potrebbe essere ucciso per OOM prima di poter loggare qualcosa.
</details>

<details>
<summary><strong>17. Un Service non sta instradando traffico ai pod. Cosa controlli?</strong></summary>
<br>

1. **Le label corrispondono**: Il `spec.selector` del Service deve corrispondere esattamente alle `metadata.labels` del pod.
2. **Esistono Endpoint**: `kubectl get endpoints <service>` — se vuoto, il selector non corrisponde a nessun pod in esecuzione.
3. **I pod sono Ready**: Solo i pod che superano le probe di readiness appaiono negli Endpoint. Controlla `kubectl get pods` per lo stato Ready.
4. **Mismatch delle porte**: Il `targetPort` del Service deve corrispondere alla porta su cui il container sta effettivamente ascoltando.
5. **Network Policy**: Una NetworkPolicy potrebbe bloccare l'ingresso ai pod.
6. **DNS**: Da un pod di debug, `nslookup <service-name>` per verificare che la risoluzione DNS funzioni.
</details>

<details>
<summary><strong>18. Come si esegue un deployment senza downtime?</strong></summary>
<br>

1. **Strategia rolling update** (predefinita): Imposta `maxUnavailable: 0` e `maxSurge: 1` per assicurare che i vecchi pod vengano rimossi solo dopo che i nuovi pod sono Ready.
2. **Probe di readiness**: Senza una probe di readiness, Kubernetes considera un pod Ready immediatamente dopo l'avvio — il traffico lo raggiunge prima che l'app sia inizializzata.
3. **PreStop hook**: Aggiungi un lifecycle hook `preStop` con un breve sleep (5-10s) per permettere alle richieste in corso di completarsi prima che il pod venga rimosso dagli endpoint del Service.
4. **PodDisruptionBudget (PDB)**: Assicura che un numero minimo di pod sia sempre disponibile durante le interruzioni volontarie (drain dei nodi, upgrade).
5. **Shutdown graceful**: L'applicazione deve gestire SIGTERM e completare le richieste attive prima di uscire.
</details>

<details>
<summary><strong>19. Cos'è un Horizontal Pod Autoscaler e come funziona?</strong></summary>
<br>

L'HPA scala automaticamente il numero di repliche dei pod in base alle metriche osservate (CPU, memoria o metriche personalizzate).

Come funziona:
1. L'HPA interroga il **Metrics Server** (o l'API delle metriche personalizzate) ogni 15 secondi.
2. Calcola: `desiredReplicas = ceil(currentReplicas × (currentMetric / targetMetric))`.
3. Se le repliche desiderate differiscono da quelle attuali, aggiorna il conteggio delle repliche del Deployment.
4. I periodi di cooldown prevengono oscillazioni: stabilizzazione scale-up (0s predefinito), stabilizzazione scale-down (300s predefinito).

Requisiti: Metrics Server installato, request delle risorse definite sui container (per metriche CPU/memoria), limiti min/max delle repliche configurati.
</details>

<details>
<summary><strong>20. Qual è la differenza tra una liveness probe e una readiness probe?</strong></summary>
<br>

- **Liveness probe**: "Il container è vivo?" Se fallisce, kubelet **uccide e riavvia** il container. Usata per rilevare deadlock o processi bloccati.
- **Readiness probe**: "Il container è pronto a servire traffico?" Se fallisce, il pod viene **rimosso dagli endpoint del Service** (nessun traffico instradato verso di esso), ma il container NON viene riavviato. Usata per periodi di warm-up, controlli delle dipendenze, sovraccarico temporaneo.

Esiste anche una **Startup probe**: Disabilita le probe liveness/readiness fino a quando l'app non è avviata. Utile per applicazioni con avvio lento per prevenire uccisioni premature.

Errore comune: Usare una liveness probe che controlla una dipendenza downstream (database). Se il database va giù, tutti i pod si riavviano — peggiorando l'interruzione. La liveness dovrebbe controllare solo l'applicazione stessa.
</details>
