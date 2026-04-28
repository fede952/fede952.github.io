---
title: "Kubernetes (K8s) Préparation aux Entretiens : Questions-Réponses Niveau Senior"
description: "20 questions avancées sur Kubernetes pour les entretiens DevOps et SRE Senior. Couvre l'architecture, le cycle de vie des pods, le réseau, le stockage, RBAC et le dépannage en production."
date: 2026-02-11
tags: ["kubernetes", "interview", "devops", "cloud-native"]
keywords: ["k8s interview questions", "cka exam prep", "kubernetes architecture questions", "kubernetes interview answers", "pod lifecycle interview", "kubernetes networking questions", "kubernetes rbac", "senior sre interview", "kubernetes troubleshooting", "helm interview questions"]
draft: false
schema_json: >
  {
    "@context": "https://schema.org",
    "@type": "TechArticle",
    "name": "Kubernetes (K8s) Préparation aux Entretiens : Questions-Réponses Niveau Senior",
    "description": "20 questions avancées sur Kubernetes couvrant l'architecture, le réseau, le stockage, la sécurité et le dépannage en production.",
    "proficiencyLevel": "Advanced",
    "inLanguage": "fr"
  }
---

## Initialisation du Système

Kubernetes est le système d'exploitation du cloud — et la compétence la plus demandée pour les rôles DevOps, SRE et Ingénierie de Plateforme. Les entretiens de niveau senior vont en profondeur : on vous interrogera sur les composants internes du control plane, les modèles réseau, le RBAC, la gestion des ressources et comment déboguer des incidents en production sous pression. Ce guide contient 20 questions qui reviennent régulièrement dans les entretiens des grandes entreprises technologiques, avec des réponses qui démontrent la profondeur attendue au niveau Staff/Senior.

**Besoin d'un rappel rapide des commandes ?** Gardez notre [Kubernetes Kubectl Cheat Sheet](/cheatsheets/kubernetes-kubectl-cheat-sheet/) ouvert pendant votre préparation.

---

## Architecture

<details>
<summary><strong>1. Décrivez les composants du control plane de Kubernetes et leurs responsabilités.</strong></summary>
<br>

Le control plane gère l'état du cluster :

- **kube-apiserver** : La porte d'entrée du cluster. Chaque commande `kubectl`, action de contrôleur et décision du scheduler passe par l'API server. Il valide et persiste l'état dans etcd.
- **etcd** : Un magasin clé-valeur distribué qui contient l'intégralité de l'état du cluster (état désiré, état actuel, configurations, secrets). C'est la seule source de vérité.
- **kube-scheduler** : Surveille les pods nouvellement créés sans nœud assigné et sélectionne un nœud en fonction des besoins en ressources, des règles d'affinité, des taints et des contraintes.
- **kube-controller-manager** : Exécute les boucles de contrôleurs (contrôleurs Deployment, ReplicaSet, Node, Job) qui réconcilient continuellement l'état désiré avec l'état actuel.
- **cloud-controller-manager** : S'intègre aux APIs du fournisseur cloud pour les LoadBalancers, le provisionnement du stockage et le cycle de vie des nœuds.
</details>

<details>
<summary><strong>2. Que se passe-t-il quand vous exécutez `kubectl apply -f deployment.yaml` ?</strong></summary>
<br>

1. `kubectl` envoie un HTTP POST/PATCH à l'**API server** avec le manifeste du Deployment.
2. L'API server **valide** la requête (authentification, autorisation via RBAC, contrôleurs d'admission).
3. L'API server écrit l'objet Deployment dans **etcd**.
4. Le **contrôleur Deployment** détecte le nouveau Deployment et crée un **ReplicaSet**.
5. Le **contrôleur ReplicaSet** le détecte et crée le nombre spécifié d'objets **Pod**.
6. Le **scheduler** détecte les pods non planifiés et assigne chacun à un nœud en fonction de la disponibilité des ressources et des contraintes.
7. Le **kubelet** sur chaque nœud assigné détecte l'assignation du pod, télécharge l'image du conteneur et démarre le conteneur via le runtime de conteneurs (containerd/CRI-O).
8. Le **kube-proxy** sur chaque nœud met à jour les règles iptables/IPVS si un Service est associé.
</details>

<details>
<summary><strong>3. Quelle est la différence entre un Deployment, un StatefulSet et un DaemonSet ?</strong></summary>
<br>

- **Deployment** : Gère les applications sans état. Les pods sont interchangeables, peuvent être mis à l'échelle librement et sont créés/détruits dans n'importe quel ordre. Idéal pour les serveurs web, APIs, workers.
- **StatefulSet** : Gère les applications avec état. Chaque pod obtient un **nom d'hôte stable** (`pod-0`, `pod-1`), un **stockage persistant** (PVC par pod) et les pods sont créés/détruits dans l'**ordre**. Idéal pour les bases de données, Kafka, ZooKeeper.
- **DaemonSet** : Assure **un pod par nœud**. Quand un nouveau nœud rejoint le cluster, un pod y est automatiquement planifié. Idéal pour les collecteurs de logs, agents de surveillance, plugins réseau.
</details>

<details>
<summary><strong>4. Expliquez le cycle de vie du pod et ses phases.</strong></summary>
<br>

Un pod traverse ces phases :

1. **Pending** : Le pod est accepté mais pas encore planifié ou les images sont en cours de téléchargement.
2. **Running** : Au moins un conteneur est en cours d'exécution ou en démarrage/redémarrage.
3. **Succeeded** : Tous les conteneurs se sont terminés avec le code 0 (pour les Jobs/charges de travail batch).
4. **Failed** : Tous les conteneurs se sont terminés, au moins un s'est terminé avec un code non nul.
5. **Unknown** : Le nœud est injoignable, l'état du pod ne peut pas être déterminé.

Au sein d'un pod en cours d'exécution, les conteneurs peuvent être dans les états : **Waiting** (téléchargement d'image, init containers), **Running**, ou **Terminated** (terminé ou crashé).
</details>

## Réseau

<details>
<summary><strong>5. Expliquez le modèle réseau de Kubernetes.</strong></summary>
<br>

Le réseau Kubernetes suit trois règles fondamentales :

1. **Chaque pod obtient sa propre adresse IP** — pas de NAT entre les pods.
2. **Tous les pods peuvent communiquer avec tous les autres pods** entre les nœuds sans NAT.
3. **L'IP qu'un pod voit pour lui-même** est la même IP que les autres utilisent pour l'atteindre.

Ceci est implémenté par les plugins CNI (Container Network Interface) comme Calico, Flannel, Cilium ou Weave. Ils créent un réseau overlay ou underlay qui satisfait ces règles. Chaque nœud obtient un sous-réseau CIDR pour les pods et le plugin CNI gère le routage entre les nœuds.
</details>

<details>
<summary><strong>6. Quelle est la différence entre les services ClusterIP, NodePort et LoadBalancer ?</strong></summary>
<br>

- **ClusterIP** (par défaut) : IP virtuelle interne uniquement. Accessible seulement depuis l'intérieur du cluster. Utilisé pour la communication inter-services.
- **NodePort** : Expose le service sur un port statique (30000-32767) sur l'IP de chaque nœud. Le trafic externe peut atteindre `<NodeIP>:<NodePort>`. S'appuie sur ClusterIP.
- **LoadBalancer** : Provisionne un équilibreur de charge externe via le fournisseur cloud. Obtient une IP/DNS publique. S'appuie sur NodePort. Utilisé pour les services publics en production.

Il existe aussi **ExternalName**, qui mappe un service vers un CNAME DNS (pas de proxying, juste de la résolution DNS).
</details>

<details>
<summary><strong>7. Qu'est-ce qu'un Ingress et en quoi diffère-t-il d'un Service ?</strong></summary>
<br>

Un **Service** opère au niveau de la couche 4 (TCP/UDP) — il route le trafic vers les pods en fonction de l'IP et du port.

Un **Ingress** opère au niveau de la couche 7 (HTTP/HTTPS) — il route le trafic en fonction du nom d'hôte et du chemin URL. Un seul Ingress peut router `api.example.com` vers le service API et `app.example.com` vers le service frontend, le tout via un seul équilibreur de charge.

Un Ingress nécessite un **Ingress Controller** (nginx-ingress, Traefik, HAProxy, AWS ALB) pour implémenter réellement les règles de routage. La ressource Ingress n'est qu'une configuration — le contrôleur fait le travail.
</details>

<details>
<summary><strong>8. Comment fonctionne le DNS à l'intérieur d'un cluster Kubernetes ?</strong></summary>
<br>

Kubernetes exécute **CoreDNS** (ou kube-dns) comme extension du cluster. Chaque service obtient un enregistrement DNS :

- `<service-name>.<namespace>.svc.cluster.local` → ClusterIP
- `<pod-ip-dashed>.<namespace>.pod.cluster.local` → Pod IP

Quand un pod fait une requête DNS pour `my-service`, le résolveur dans `/etc/resolv.conf` (configuré par kubelet) ajoute les domaines de recherche et interroge CoreDNS. CoreDNS surveille l'API server pour les changements de Service/Endpoint et met à jour ses enregistrements automatiquement.
</details>

## Stockage

<details>
<summary><strong>9. Expliquez PersistentVolume (PV), PersistentVolumeClaim (PVC) et StorageClass.</strong></summary>
<br>

- **PersistentVolume (PV)** : Un morceau de stockage provisionné par un administrateur ou dynamiquement par une StorageClass. Il existe indépendamment de tout pod. Il a un cycle de vie séparé des pods.
- **PersistentVolumeClaim (PVC)** : Une demande de stockage par un pod. Spécifie la taille, le mode d'accès et optionnellement une StorageClass. Kubernetes lie le PVC à un PV correspondant.
- **StorageClass** : Définit une classe de stockage (SSD, HDD, NFS) et le provisionneur qui crée des PVs dynamiquement. Permet le provisionnement de stockage à la demande — aucune intervention d'administrateur nécessaire.

Flux : Pod référence PVC → PVC demande du stockage à la StorageClass → StorageClass déclenche le provisionneur → Provisionneur crée PV → PVC se lie au PV → Pod monte le PV.
</details>

<details>
<summary><strong>10. Quels sont les modes d'accès et les politiques de récupération ?</strong></summary>
<br>

**Modes d'Accès** :
- **ReadWriteOnce (RWO)** : Monté en lecture/écriture par un seul nœud. Le plus courant (AWS EBS, GCE PD).
- **ReadOnlyMany (ROX)** : Monté en lecture seule par plusieurs nœuds. Utilisé pour les configurations partagées.
- **ReadWriteMany (RWX)** : Monté en lecture/écriture par plusieurs nœuds. Nécessite un stockage réseau (NFS, EFS, CephFS).

**Politiques de Récupération** (ce qui se passe quand le PVC est supprimé) :
- **Retain** : Le PV est conservé avec ses données. L'administrateur doit le récupérer manuellement.
- **Delete** : Le PV et le stockage sous-jacent sont supprimés. Par défaut pour le provisionnement dynamique.
- **Recycle** (obsolète) : `rm -rf` basique sur le volume. Utilisez Retain ou Delete à la place.
</details>

## Sécurité et RBAC

<details>
<summary><strong>11. Comment fonctionne le RBAC dans Kubernetes ?</strong></summary>
<br>

Le RBAC (Contrôle d'Accès Basé sur les Rôles) a quatre objets :

- **Role** : Définit les permissions (verbes : get, list, create, delete) sur les ressources (pods, services, secrets) au sein d'un **seul namespace**.
- **ClusterRole** : Identique au Role mais à **l'échelle du cluster** (tous les namespaces, ou ressources à portée cluster comme les nœuds).
- **RoleBinding** : Lie un Role à un utilisateur, groupe ou compte de service au sein d'un namespace.
- **ClusterRoleBinding** : Lie un ClusterRole à un sujet à travers tout le cluster.

Principe : Commencez avec les permissions minimales nécessaires. Ne liez jamais `cluster-admin` aux comptes de service des applications. Auditez le RBAC régulièrement avec `kubectl auth can-i`.
</details>

<details>
<summary><strong>12. Que sont les Pod Security Standards (PSS) ?</strong></summary>
<br>

Les Pod Security Standards ont remplacé les PodSecurityPolicies (supprimées dans K8s 1.25). Ils définissent trois niveaux de sécurité :

- **Privileged** : Sans restriction. Autorise tout. Utilisé pour les pods au niveau système (plugins CNI, pilotes de stockage).
- **Baseline** : Empêche les escalades de privilèges connues. Bloque hostNetwork, hostPID, conteneurs privilégiés, mais autorise la plupart des charges de travail.
- **Restricted** : Sécurité maximale. Exige non-root, suppression de toutes les capabilities, système de fichiers racine en lecture seule, pas d'escalade de privilèges.

Appliqué via le contrôleur **Pod Security Admission** au niveau du namespace à l'aide d'étiquettes :
```yaml
metadata:
  labels:
    pod-security.kubernetes.io/enforce: restricted
```
</details>

<details>
<summary><strong>13. Comment gérer les secrets dans Kubernetes de manière sécurisée ?</strong></summary>
<br>

Les secrets Kubernetes par défaut sont **encodés en base64, pas chiffrés**. Toute personne ayant accès à l'API peut les décoder.

Étapes de renforcement :
1. **Activer le chiffrement au repos** dans etcd (`EncryptionConfiguration` avec AES-CBC ou fournisseur KMS).
2. **Utiliser des gestionnaires de secrets externes** (Vault, AWS Secrets Manager) avec l'External Secrets Operator ou le CSI Secrets Store Driver.
3. **RBAC** : Restreindre `get`/`list` sur les secrets uniquement aux comptes de service qui en ont besoin.
4. **Monter comme fichiers**, pas comme variables d'environnement — les variables d'environnement peuvent fuiter via les logs, les dumps de crash et `/proc`.
5. **Effectuer la rotation des secrets** régulièrement et utiliser des identifiants à courte durée de vie lorsque possible.
</details>

## Planification et Ressources

<details>
<summary><strong>14. Expliquez les demandes et limites de ressources.</strong></summary>
<br>

- **Demandes (Requests)** : La quantité de CPU/mémoire **garantie** au conteneur. Le scheduler utilise les demandes pour décider quel nœud a suffisamment de capacité.
- **Limites (Limits)** : La quantité **maximale** qu'un conteneur peut utiliser. Si un conteneur dépasse sa limite mémoire, il est tué par OOM. S'il dépasse la limite CPU, il est ralenti.

Classes QoS basées sur les demandes/limites :
- **Guaranteed** : Demandes == Limites pour tous les conteneurs. Priorité la plus élevée, dernier à être évincé.
- **Burstable** : Demandes < Limites. Priorité moyenne.
- **BestEffort** : Aucune demande ni limite définie. Premier à être évincé sous pression.

Bonne pratique : Définissez toujours les demandes (pour la précision de la planification) et les limites (pour la stabilité du cluster).
</details>

<details>
<summary><strong>15. Que sont les taints, tolerations et la node affinity ?</strong></summary>
<br>

- **Taints** sont appliqués aux nœuds : "Ne planifiez pas de pods ici à moins qu'ils ne tolèrent ce taint." Exemple : `kubectl taint nodes gpu-node gpu=true:NoSchedule`.
- **Tolerations** sont appliquées aux pods : "Je peux tolérer ce taint." Les pods avec des tolerations correspondantes peuvent être planifiés sur des nœuds avec des taints.
- **Node Affinity** est une spécification du pod qui dit "Préférer ou exiger la planification sur des nœuds avec des étiquettes spécifiques." Exemple : exiger des nœuds avec `disktype=ssd`.

Utiliser ensemble : Appliquer des taints aux nœuds GPU → seuls les pods avec des tolerations GPU et une affinité GPU y atterrissent. Empêche les charges de travail non-GPU de gaspiller du matériel coûteux.
</details>

## Dépannage

<details>
<summary><strong>16. Un pod est bloqué en CrashLoopBackOff. Comment le déboguez-vous ?</strong></summary>
<br>

`CrashLoopBackOff` signifie que le conteneur continue de crasher et Kubernetes attend avant de le redémarrer (délai exponentiel jusqu'à 5 minutes).

Étapes de débogage :
1. `kubectl describe pod <name>` — vérifiez Events, Last State, Exit Code.
2. `kubectl logs <pod> --previous` — lisez les logs de l'instance qui a crashé.
3. Analyse du code de sortie : 1 = erreur application, 137 = tué par OOM, 139 = segfault, 143 = SIGTERM.
4. Si le conteneur crashe trop vite pour les logs : `kubectl run debug --image=<image> --command -- sleep 3600` et faites exec pour inspecter l'environnement.
5. Vérifiez si les sondes de readiness/liveness sont mal configurées (sonde pointant vers le mauvais port/chemin).
6. Vérifiez les limites de ressources — le conteneur peut être tué par OOM avant de pouvoir enregistrer quoi que ce soit.
</details>

<details>
<summary><strong>17. Un Service ne route pas le trafic vers les pods. Que vérifiez-vous ?</strong></summary>
<br>

1. **Les étiquettes correspondent** : Le `spec.selector` du Service doit correspondre exactement aux `metadata.labels` du pod.
2. **Les Endpoints existent** : `kubectl get endpoints <service>` — si vide, le sélecteur ne correspond à aucun pod en cours d'exécution.
3. **Les pods sont Ready** : Seuls les pods passant les sondes de readiness apparaissent dans les Endpoints. Vérifiez `kubectl get pods` pour le statut Ready.
4. **Inadéquation des ports** : Le `targetPort` du Service doit correspondre au port sur lequel le conteneur écoute réellement.
5. **Network Policy** : Une NetworkPolicy pourrait bloquer l'entrée vers les pods.
6. **DNS** : Depuis un pod de débogage, `nslookup <service-name>` pour vérifier que la résolution DNS fonctionne.
</details>

<details>
<summary><strong>18. Comment effectuer un déploiement sans temps d'arrêt ?</strong></summary>
<br>

1. **Stratégie de rolling update** (par défaut) : Définissez `maxUnavailable: 0` et `maxSurge: 1` pour garantir que les anciens pods ne sont supprimés qu'après que les nouveaux pods sont Ready.
2. **Sondes de readiness** : Sans sonde de readiness, Kubernetes considère un pod Ready immédiatement après le démarrage — le trafic l'atteint avant que l'application ne soit initialisée.
3. **PreStop hook** : Ajoutez un hook de cycle de vie `preStop` avec un court sleep (5-10s) pour permettre aux requêtes en cours de se terminer avant que le pod ne soit retiré des endpoints du Service.
4. **PodDisruptionBudget (PDB)** : Garantit qu'un nombre minimum de pods est toujours disponible pendant les perturbations volontaires (drains de nœuds, mises à jour).
5. **Arrêt gracieux** : L'application doit gérer SIGTERM et terminer les requêtes actives avant de quitter.
</details>

<details>
<summary><strong>19. Qu'est-ce qu'un Horizontal Pod Autoscaler et comment fonctionne-t-il ?</strong></summary>
<br>

Le HPA met automatiquement à l'échelle le nombre de répliques de pods en fonction des métriques observées (CPU, mémoire ou métriques personnalisées).

Comment ça fonctionne :
1. Le HPA interroge le **Metrics Server** (ou l'API de métriques personnalisées) toutes les 15 secondes.
2. Il calcule : `desiredReplicas = ceil(currentReplicas × (currentMetric / targetMetric))`.
3. Si les répliques désirées diffèrent des actuelles, il met à jour le nombre de répliques du Deployment.
4. Les périodes de refroidissement empêchent les oscillations : stabilisation de la montée en charge (0s par défaut), stabilisation de la réduction (300s par défaut).

Prérequis : Metrics Server installé, demandes de ressources définies sur les conteneurs (pour les métriques CPU/mémoire), limites min/max de répliques configurées.
</details>

<details>
<summary><strong>20. Quelle est la différence entre une sonde de liveness et une sonde de readiness ?</strong></summary>
<br>

- **Sonde de liveness** : "Le conteneur est-il vivant ?" Si elle échoue, kubelet **tue et redémarre** le conteneur. Utilisée pour détecter les deadlocks ou les processus gelés.
- **Sonde de readiness** : "Le conteneur est-il prêt à servir du trafic ?" Si elle échoue, le pod est **retiré des endpoints du Service** (pas de trafic routé vers lui), mais le conteneur N'EST PAS redémarré. Utilisée pour les périodes de préchauffage, les vérifications de dépendances, la surcharge temporaire.

Il existe aussi une **Sonde de startup** : Désactive les sondes de liveness/readiness jusqu'à ce que l'application ait démarré. Utile pour les applications à démarrage lent pour éviter les arrêts prématurés.

Erreur courante : Utiliser une sonde de liveness qui vérifie une dépendance en aval (base de données). Si la base de données tombe, tous les pods redémarrent — aggravant la panne. La liveness ne devrait vérifier que l'application elle-même.
</details>
