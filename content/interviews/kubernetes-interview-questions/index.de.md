---
title: "Kubernetes (K8s) Interview-Vorbereitung: Fragen und Antworten auf Senior-Level"
description: "20 fortgeschrittene Kubernetes-Interviewfragen für Senior DevOps und SRE Rollen. Behandelt Architektur, Pod-Lebenszyklus, Netzwerk, Speicher, RBAC und Troubleshooting in der Produktion."
date: 2026-02-11
tags: ["kubernetes", "interview", "devops", "cloud-native"]
keywords: ["k8s interview questions", "cka exam prep", "kubernetes architecture questions", "kubernetes interview answers", "pod lifecycle interview", "kubernetes networking questions", "kubernetes rbac", "senior sre interview", "kubernetes troubleshooting", "helm interview questions"]
draft: false
schema_json: >
  {
    "@context": "https://schema.org",
    "@type": "TechArticle",
    "name": "Kubernetes (K8s) Interview-Vorbereitung: Fragen und Antworten auf Senior-Level",
    "description": "20 fortgeschrittene Kubernetes-Interviewfragen zu Architektur, Netzwerk, Speicher, Sicherheit und Troubleshooting in der Produktion.",
    "proficiencyLevel": "Advanced",
    "inLanguage": "de"
  }
---

## System-Initialisierung

Kubernetes ist das Betriebssystem der Cloud — und die gefragteste Fähigkeit für DevOps-, SRE- und Platform-Engineering-Rollen. Interviews auf Senior-Level gehen in die Tiefe: Sie werden nach den Interna der Control Plane, Netzwerkmodellen, RBAC, Ressourcenverwaltung und dem Debugging von Produktionsvorfällen unter Druck gefragt. Dieser Leitfaden enthält 20 Fragen, die wiederholt in Interviews bei Top-Technologieunternehmen auftauchen, mit Antworten, die die auf Staff/Senior-Level erwartete Tiefe demonstrieren.

**Brauchen Sie eine schnelle Befehlsauffrischung?** Halten Sie unser [Kubernetes Kubectl Cheat Sheet](/cheatsheets/kubernetes-kubectl-cheat-sheet/) während Ihrer Vorbereitung offen.

---

## Architektur

<details>
<summary><strong>1. Beschreiben Sie die Kubernetes Control Plane-Komponenten und ihre Verantwortlichkeiten.</strong></summary>
<br>

Die Control Plane verwaltet den Cluster-Zustand:

- **kube-apiserver**: Das Eingangstor zum Cluster. Jeder `kubectl`-Befehl, jede Controller-Aktion und Scheduler-Entscheidung läuft über den API-Server. Er validiert und persistiert den Zustand in etcd.
- **etcd**: Ein verteilter Key-Value-Store, der den gesamten Cluster-Zustand enthält (gewünschter Zustand, aktueller Zustand, Konfigurationen, Secrets). Es ist die einzige Quelle der Wahrheit.
- **kube-scheduler**: Überwacht neu erstellte Pods ohne zugewiesenen Node und wählt einen Node basierend auf Ressourcenanforderungen, Affinitätsregeln, Taints und Einschränkungen aus.
- **kube-controller-manager**: Führt Controller-Schleifen aus (Deployment-, ReplicaSet-, Node-, Job-Controller), die kontinuierlich den gewünschten Zustand mit dem aktuellen Zustand abgleichen.
- **cloud-controller-manager**: Integriert sich mit Cloud-Provider-APIs für LoadBalancer, Speicherprovisionierung und Node-Lebenszyklus.
</details>

<details>
<summary><strong>2. Was passiert, wenn Sie `kubectl apply -f deployment.yaml` ausführen?</strong></summary>
<br>

1. `kubectl` sendet einen HTTP POST/PATCH an den **API-Server** mit dem Deployment-Manifest.
2. Der API-Server **validiert** die Anfrage (Authentifizierung, Autorisierung über RBAC, Admission-Controller).
3. Der API-Server schreibt das Deployment-Objekt in **etcd**.
4. Der **Deployment-Controller** erkennt das neue Deployment und erstellt ein **ReplicaSet**.
5. Der **ReplicaSet-Controller** erkennt es und erstellt die angegebene Anzahl von **Pod**-Objekten.
6. Der **Scheduler** erkennt nicht geplante Pods und weist jeden einem Node zu, basierend auf Ressourcenverfügbarkeit und Einschränkungen.
7. Das **kubelet** auf jedem zugewiesenen Node erkennt die Pod-Zuweisung, lädt das Container-Image herunter und startet den Container über die Container-Runtime (containerd/CRI-O).
8. Der **kube-proxy** auf jedem Node aktualisiert iptables/IPVS-Regeln, wenn ein Service zugeordnet ist.
</details>

<details>
<summary><strong>3. Was ist der Unterschied zwischen einem Deployment, StatefulSet und DaemonSet?</strong></summary>
<br>

- **Deployment**: Verwaltet zustandslose Anwendungen. Pods sind austauschbar, können frei skaliert werden und werden in beliebiger Reihenfolge erstellt/zerstört. Am besten für Webserver, APIs, Worker.
- **StatefulSet**: Verwaltet zustandsbehaftete Anwendungen. Jeder Pod bekommt einen **stabilen Hostnamen** (`pod-0`, `pod-1`), **persistenten Speicher** (PVC pro Pod) und Pods werden in **Reihenfolge** erstellt/zerstört. Am besten für Datenbanken, Kafka, ZooKeeper.
- **DaemonSet**: Stellt **einen Pod pro Node** sicher. Wenn ein neuer Node dem Cluster beitritt, wird automatisch ein Pod darauf geplant. Am besten für Log-Kollektoren, Monitoring-Agenten, Netzwerk-Plugins.
</details>

<details>
<summary><strong>4. Erklären Sie den Pod-Lebenszyklus und seine Phasen.</strong></summary>
<br>

Ein Pod durchläuft diese Phasen:

1. **Pending**: Der Pod ist akzeptiert, aber noch nicht geplant oder Images werden heruntergeladen.
2. **Running**: Mindestens ein Container läuft oder startet/startet neu.
3. **Succeeded**: Alle Container wurden mit Code 0 beendet (für Jobs/Batch-Workloads).
4. **Failed**: Alle Container wurden beendet, mindestens einer mit einem Nicht-Null-Code.
5. **Unknown**: Der Node ist unerreichbar, der Pod-Zustand kann nicht bestimmt werden.

Innerhalb eines laufenden Pods können Container in den Zuständen sein: **Waiting** (Image wird heruntergeladen, Init-Container), **Running** oder **Terminated** (beendet oder abgestürzt).
</details>

## Netzwerk

<details>
<summary><strong>5. Erklären Sie das Kubernetes-Netzwerkmodell.</strong></summary>
<br>

Das Kubernetes-Netzwerk folgt drei grundlegenden Regeln:

1. **Jeder Pod bekommt seine eigene IP-Adresse** — kein NAT zwischen Pods.
2. **Alle Pods können mit allen anderen Pods** über Nodes hinweg ohne NAT kommunizieren.
3. **Die IP, die ein Pod für sich selbst sieht**, ist dieselbe IP, die andere verwenden, um ihn zu erreichen.

Dies wird durch CNI (Container Network Interface)-Plugins wie Calico, Flannel, Cilium oder Weave implementiert. Sie erstellen ein Overlay- oder Underlay-Netzwerk, das diese Regeln erfüllt. Jeder Node bekommt ein Pod-CIDR-Subnetz, und das CNI-Plugin kümmert sich um das Routing zwischen Nodes.
</details>

<details>
<summary><strong>6. Was ist der Unterschied zwischen ClusterIP-, NodePort- und LoadBalancer-Services?</strong></summary>
<br>

- **ClusterIP** (Standard): Nur interne virtuelle IP. Nur von innerhalb des Clusters erreichbar. Wird für die Kommunikation zwischen Services verwendet.
- **NodePort**: Exponiert den Service auf einem statischen Port (30000-32767) auf der IP jedes Nodes. Externer Traffic kann `<NodeIP>:<NodePort>` erreichen. Baut auf ClusterIP auf.
- **LoadBalancer**: Provisioniert einen externen Load Balancer über den Cloud-Provider. Bekommt eine öffentliche IP/DNS. Baut auf NodePort auf. Wird für öffentlich zugängliche Produktions-Services verwendet.

Es gibt auch **ExternalName**, das einen Service auf einen DNS-CNAME abbildet (kein Proxying, nur DNS-Auflösung).
</details>

<details>
<summary><strong>7. Was ist ein Ingress und wie unterscheidet er sich von einem Service?</strong></summary>
<br>

Ein **Service** arbeitet auf Schicht 4 (TCP/UDP) — er routet Traffic zu Pods basierend auf IP und Port.

Ein **Ingress** arbeitet auf Schicht 7 (HTTP/HTTPS) — er routet Traffic basierend auf Hostname und URL-Pfad. Ein einzelner Ingress kann `api.example.com` zum API-Service und `app.example.com` zum Frontend-Service routen, alles über einen einzigen Load Balancer.

Ein Ingress benötigt einen **Ingress Controller** (nginx-ingress, Traefik, HAProxy, AWS ALB), um die Routing-Regeln tatsächlich zu implementieren. Die Ingress-Ressource ist nur eine Konfiguration — der Controller erledigt die Arbeit.
</details>

<details>
<summary><strong>8. Wie funktioniert DNS innerhalb eines Kubernetes-Clusters?</strong></summary>
<br>

Kubernetes betreibt **CoreDNS** (oder kube-dns) als Cluster-Add-on. Jeder Service bekommt einen DNS-Eintrag:

- `<service-name>.<namespace>.svc.cluster.local` → ClusterIP
- `<pod-ip-dashed>.<namespace>.pod.cluster.local` → Pod IP

Wenn ein Pod eine DNS-Abfrage für `my-service` macht, fügt der Resolver in `/etc/resolv.conf` (von kubelet konfiguriert) die Suchdomänen hinzu und fragt CoreDNS ab. CoreDNS überwacht den API-Server auf Service/Endpoint-Änderungen und aktualisiert seine Einträge automatisch.
</details>

## Speicher

<details>
<summary><strong>9. Erklären Sie PersistentVolume (PV), PersistentVolumeClaim (PVC) und StorageClass.</strong></summary>
<br>

- **PersistentVolume (PV)**: Ein Stück Speicher, das von einem Administrator oder dynamisch durch eine StorageClass provisioniert wird. Es existiert unabhängig von jedem Pod. Hat einen vom Pod getrennten Lebenszyklus.
- **PersistentVolumeClaim (PVC)**: Eine Speicheranforderung durch einen Pod. Gibt Größe, Zugriffsmodus und optional eine StorageClass an. Kubernetes bindet den PVC an einen passenden PV.
- **StorageClass**: Definiert eine Speicherklasse (SSD, HDD, NFS) und den Provisioner, der PVs dynamisch erstellt. Ermöglicht Speicherprovisionierung auf Abruf — kein Administrator-Eingriff nötig.

Ablauf: Pod referenziert PVC → PVC fordert Speicher von StorageClass an → StorageClass löst Provisioner aus → Provisioner erstellt PV → PVC bindet an PV → Pod mountet PV.
</details>

<details>
<summary><strong>10. Was sind Zugriffsmodi und Rückforderungsrichtlinien?</strong></summary>
<br>

**Zugriffsmodi**:
- **ReadWriteOnce (RWO)**: Lese-/Schreibzugriff durch einen einzelnen Node. Am häufigsten (AWS EBS, GCE PD).
- **ReadOnlyMany (ROX)**: Nur-Lese-Zugriff durch viele Nodes. Wird für gemeinsame Konfigurationen verwendet.
- **ReadWriteMany (RWX)**: Lese-/Schreibzugriff durch viele Nodes. Erfordert Netzwerkspeicher (NFS, EFS, CephFS).

**Rückforderungsrichtlinien** (was passiert, wenn der PVC gelöscht wird):
- **Retain**: PV wird mit seinen Daten behalten. Administrator muss es manuell zurückfordern.
- **Delete**: PV und zugrunde liegender Speicher werden gelöscht. Standard für dynamische Provisionierung.
- **Recycle** (veraltet): Einfaches `rm -rf` auf dem Volume. Verwenden Sie stattdessen Retain oder Delete.
</details>

## Sicherheit und RBAC

<details>
<summary><strong>11. Wie funktioniert RBAC in Kubernetes?</strong></summary>
<br>

RBAC (Rollenbasierte Zugriffskontrolle) hat vier Objekte:

- **Role**: Definiert Berechtigungen (Verben: get, list, create, delete) auf Ressourcen (Pods, Services, Secrets) innerhalb eines **einzelnen Namespace**.
- **ClusterRole**: Wie Role, aber **clusterweit** (alle Namespaces oder cluster-bezogene Ressourcen wie Nodes).
- **RoleBinding**: Bindet eine Role an einen Benutzer, eine Gruppe oder ein Service-Konto innerhalb eines Namespace.
- **ClusterRoleBinding**: Bindet eine ClusterRole an ein Subjekt über den gesamten Cluster hinweg.

Prinzip: Beginnen Sie mit den minimal nötigen Berechtigungen. Binden Sie niemals `cluster-admin` an Anwendungs-Service-Konten. Überprüfen Sie RBAC regelmäßig mit `kubectl auth can-i`.
</details>

<details>
<summary><strong>12. Was sind Pod Security Standards (PSS)?</strong></summary>
<br>

Pod Security Standards haben PodSecurityPolicies ersetzt (in K8s 1.25 entfernt). Sie definieren drei Sicherheitsstufen:

- **Privileged**: Uneingeschränkt. Erlaubt alles. Wird für System-Level-Pods verwendet (CNI-Plugins, Speichertreiber).
- **Baseline**: Verhindert bekannte Privilegienerweiterungen. Blockiert hostNetwork, hostPID, privilegierte Container, erlaubt aber die meisten Workloads.
- **Restricted**: Maximale Sicherheit. Erfordert non-root, alle Capabilities entfernen, Nur-Lese-Root-Dateisystem, keine Privilegienerweiterung.

Durchgesetzt über den **Pod Security Admission**-Controller auf Namespace-Ebene mittels Labels:
```yaml
metadata:
  labels:
    pod-security.kubernetes.io/enforce: restricted
```
</details>

<details>
<summary><strong>13. Wie verwaltet man Secrets in Kubernetes sicher?</strong></summary>
<br>

Standard-Kubernetes-Secrets sind **base64-kodiert, nicht verschlüsselt**. Jeder mit API-Zugriff kann sie dekodieren.

Härtungsschritte:
1. **Verschlüsselung im Ruhezustand aktivieren** in etcd (`EncryptionConfiguration` mit AES-CBC oder KMS-Provider).
2. **Externe Secret-Manager verwenden** (Vault, AWS Secrets Manager) mit dem External Secrets Operator oder CSI Secrets Store Driver.
3. **RBAC**: `get`/`list` auf Secrets nur auf die Service-Konten beschränken, die sie benötigen.
4. **Als Dateien mounten**, nicht als Umgebungsvariablen — Umgebungsvariablen können über Logs, Crash-Dumps und `/proc` geleakt werden.
5. **Secrets regelmäßig rotieren** und kurzlebige Anmeldedaten verwenden, wo möglich.
</details>

## Scheduling und Ressourcen

<details>
<summary><strong>14. Erklären Sie Ressourcenanforderungen und -limits.</strong></summary>
<br>

- **Requests**: Die Menge an CPU/Speicher, die dem Container **garantiert** wird. Der Scheduler verwendet Requests, um zu entscheiden, welcher Node genug Kapazität hat.
- **Limits**: Die **maximale** Menge, die ein Container verwenden kann. Wenn ein Container sein Speicherlimit überschreitet, wird er per OOM-Kill beendet. Bei CPU-Limit-Überschreitung wird er gedrosselt.

QoS-Klassen basierend auf Requests/Limits:
- **Guaranteed**: Requests == Limits für alle Container. Höchste Priorität, wird als letztes evakuiert.
- **Burstable**: Requests < Limits. Mittlere Priorität.
- **BestEffort**: Keine Requests oder Limits gesetzt. Wird als erstes unter Druck evakuiert.

Best Practice: Setzen Sie immer Requests (für Scheduling-Genauigkeit) und Limits (für Cluster-Stabilität).
</details>

<details>
<summary><strong>15. Was sind Taints, Tolerations und Node Affinity?</strong></summary>
<br>

- **Taints** werden auf Nodes angewendet: "Plane keine Pods hier, es sei denn, sie tolerieren diesen Taint." Beispiel: `kubectl taint nodes gpu-node gpu=true:NoSchedule`.
- **Tolerations** werden auf Pods angewendet: "Ich kann diesen Taint tolerieren." Pods mit passenden Tolerations können auf Nodes mit Taints geplant werden.
- **Node Affinity** ist eine Pod-Spezifikation, die sagt: "Bevorzuge oder verlange die Planung auf Nodes mit bestimmten Labels." Beispiel: Nodes mit `disktype=ssd` verlangen.

Zusammen verwenden: GPU-Nodes mit Taints versehen → nur Pods mit GPU-Tolerations und GPU-Affinität landen dort. Verhindert, dass Nicht-GPU-Workloads teure Hardware verschwenden.
</details>

## Fehlerbehebung

<details>
<summary><strong>16. Ein Pod steckt in CrashLoopBackOff fest. Wie debuggen Sie das?</strong></summary>
<br>

`CrashLoopBackOff` bedeutet, dass der Container immer wieder abstürzt und Kubernetes mit dem Neustart wartet (exponentieller Backoff bis zu 5 Minuten).

Debug-Schritte:
1. `kubectl describe pod <name>` — Events, Last State, Exit Code prüfen.
2. `kubectl logs <pod> --previous` — Logs der abgestürzten Instanz lesen.
3. Exit-Code-Analyse: 1 = Anwendungsfehler, 137 = OOM-Kill, 139 = Segfault, 143 = SIGTERM.
4. Wenn der Container zu schnell für Logs abstürzt: `kubectl run debug --image=<image> --command -- sleep 3600` und per exec die Umgebung inspizieren.
5. Prüfen, ob Readiness-/Liveness-Probes falsch konfiguriert sind (Probe trifft falschen Port/Pfad).
6. Ressourcenlimits prüfen — der Container könnte per OOM-Kill beendet werden, bevor er etwas loggen kann.
</details>

<details>
<summary><strong>17. Ein Service routet keinen Traffic zu Pods. Was prüfen Sie?</strong></summary>
<br>

1. **Labels stimmen überein**: Der `spec.selector` des Service muss genau mit den `metadata.labels` des Pods übereinstimmen.
2. **Endpoints existieren**: `kubectl get endpoints <service>` — wenn leer, passt der Selector zu keinem laufenden Pod.
3. **Pods sind Ready**: Nur Pods, die Readiness-Probes bestehen, erscheinen in den Endpoints. Prüfen Sie `kubectl get pods` auf Ready-Status.
4. **Port-Diskrepanz**: Der `targetPort` des Service muss mit dem Port übereinstimmen, auf dem der Container tatsächlich lauscht.
5. **Network Policy**: Eine NetworkPolicy könnte den Eingang zu den Pods blockieren.
6. **DNS**: Von einem Debug-Pod aus `nslookup <service-name>` ausführen, um die DNS-Auflösung zu verifizieren.
</details>

<details>
<summary><strong>18. Wie führen Sie ein Zero-Downtime-Deployment durch?</strong></summary>
<br>

1. **Rolling-Update-Strategie** (Standard): Setzen Sie `maxUnavailable: 0` und `maxSurge: 1`, um sicherzustellen, dass alte Pods erst entfernt werden, nachdem neue Pods Ready sind.
2. **Readiness-Probes**: Ohne Readiness-Probe betrachtet Kubernetes einen Pod sofort nach dem Start als Ready — Traffic trifft ihn, bevor die Anwendung initialisiert ist.
3. **PreStop-Hook**: Fügen Sie einen `preStop`-Lifecycle-Hook mit einem kurzen Sleep (5-10s) hinzu, damit laufende Anfragen abgeschlossen werden können, bevor der Pod aus den Service-Endpoints entfernt wird.
4. **PodDisruptionBudget (PDB)**: Stellt sicher, dass eine Mindestanzahl von Pods während freiwilliger Störungen (Node-Drains, Upgrades) immer verfügbar ist.
5. **Graceful Shutdown**: Die Anwendung muss SIGTERM verarbeiten und aktive Anfragen beenden, bevor sie sich beendet.
</details>

<details>
<summary><strong>19. Was ist ein Horizontal Pod Autoscaler und wie funktioniert er?</strong></summary>
<br>

Der HPA skaliert automatisch die Anzahl der Pod-Replikas basierend auf beobachteten Metriken (CPU, Speicher oder benutzerdefinierte Metriken).

Funktionsweise:
1. Der HPA fragt den **Metrics Server** (oder die Custom-Metrics-API) alle 15 Sekunden ab.
2. Er berechnet: `desiredReplicas = ceil(currentReplicas × (currentMetric / targetMetric))`.
3. Wenn die gewünschten Replikas von den aktuellen abweichen, aktualisiert er die Replika-Anzahl des Deployments.
4. Abkühlungsperioden verhindern Schwankungen: Scale-up-Stabilisierung (Standard 0s), Scale-down-Stabilisierung (Standard 300s).

Voraussetzungen: Metrics Server installiert, Ressourcenanforderungen auf Containern definiert (für CPU/Speicher-Metriken), Min/Max-Replika-Grenzen konfiguriert.
</details>

<details>
<summary><strong>20. Was ist der Unterschied zwischen einer Liveness-Probe und einer Readiness-Probe?</strong></summary>
<br>

- **Liveness-Probe**: "Lebt der Container?" Wenn sie fehlschlägt, **beendet und startet kubelet den Container neu**. Wird verwendet, um Deadlocks oder eingefrorene Prozesse zu erkennen.
- **Readiness-Probe**: "Ist der Container bereit, Traffic zu bedienen?" Wenn sie fehlschlägt, wird der Pod **aus den Service-Endpoints entfernt** (kein Traffic wird zu ihm geroutet), aber der Container wird NICHT neu gestartet. Wird für Aufwärmphasen, Abhängigkeitsprüfungen, temporäre Überlastung verwendet.

Es gibt auch eine **Startup-Probe**: Deaktiviert Liveness-/Readiness-Probes, bis die Anwendung gestartet ist. Nützlich für langsam startende Anwendungen, um vorzeitige Kills zu verhindern.

Häufiger Fehler: Eine Liveness-Probe verwenden, die eine nachgelagerte Abhängigkeit prüft (Datenbank). Wenn die Datenbank ausfällt, starten alle Pods neu — was den Ausfall verschlimmert. Liveness sollte nur die Anwendung selbst prüfen.
</details>
