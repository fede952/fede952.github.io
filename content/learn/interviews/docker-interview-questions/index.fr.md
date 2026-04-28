---
title: "Top 20 des Questions d'Entretien Docker et Réponses (Édition 2026)"
description: "Réussissez votre entretien Senior DevOps avec ces 20 questions avancées sur Docker couvrant les conteneurs, images, réseaux, volumes, Docker Compose et les bonnes pratiques de production."
date: 2026-02-11
tags: ["docker", "interview", "devops", "containers"]
keywords: ["questions entretien docker", "entretien senior devops", "questions conteneurisation", "réponses entretien docker", "entretien docker compose", "bonnes pratiques dockerfile", "entretien orchestration conteneurs", "questions réseau docker", "entretien ingénieur devops", "questions docker production"]
draft: false
schema_json: >
  {
    "@context": "https://schema.org",
    "@type": "TechArticle",
    "name": "Top 20 des Questions d'Entretien Docker et Réponses (Édition 2026)",
    "description": "Questions avancées d'entretien Docker pour les rôles Senior DevOps couvrant les conteneurs, images, réseaux et bonnes pratiques de production.",
    "proficiencyLevel": "Advanced",
    "inLanguage": "fr"
  }
---

## Initialisation du Système

Docker est devenu une compétence incontournable pour tout rôle DevOps, SRE ou ingénierie backend. Les recruteurs au niveau senior s'attendent à ce que vous alliez au-delà de `docker run` — ils veulent voir que vous comprenez la stratification des images, les mécanismes internes du réseau, le renforcement de la sécurité et les patterns d'orchestration en production. Ce guide contient les 20 questions les plus fréquemment posées lors d'entretiens de niveau Senior et Lead, avec des réponses détaillées qui démontrent la profondeur.

**Besoin d'un rappel rapide des commandes avant votre entretien ?** Ajoutez à vos favoris notre [Cheatsheet Docker Captain's Log](/cheatsheets/docker-container-commands/).

---

## Concepts Fondamentaux

<details>
<summary><strong>1. Quelle est la différence entre un conteneur et une machine virtuelle ?</strong></summary>
<br>

Une **machine virtuelle** exécute un système d'exploitation invité complet sur un hyperviseur, incluant son propre noyau, pilotes et bibliothèques système. Chaque VM est complètement isolée mais consomme des ressources significatives (Go de RAM, minutes pour démarrer).

Un **conteneur** partage le noyau du système d'exploitation hôte et isole les processus en utilisant les namespaces Linux et les cgroups. Il ne contient que l'application et ses dépendances — pas de noyau séparé. Cela rend les conteneurs légers (Mo), rapides à démarrer (millisecondes) et hautement portables.

Différence clé : Les VMs virtualisent le **matériel**, les conteneurs virtualisent le **système d'exploitation**.
</details>

<details>
<summary><strong>2. Que sont les couches d'images Docker et comment fonctionnent-elles ?</strong></summary>
<br>

Une image Docker est construite à partir d'une série de **couches en lecture seule**. Chaque instruction dans un Dockerfile (`FROM`, `RUN`, `COPY`, etc.) crée une nouvelle couche. Les couches sont empilées les unes sur les autres en utilisant un système de fichiers union (comme OverlayFS).

Lorsqu'un conteneur s'exécute, Docker ajoute une fine **couche inscriptible** au sommet (la couche du conteneur). Les modifications effectuées à l'exécution n'affectent que cette couche inscriptible — les couches sous-jacentes de l'image restent inchangées.

Cette architecture permet :
- **Mise en cache** : Si une couche n'a pas changé, Docker la réutilise depuis le cache lors des constructions.
- **Partage** : Plusieurs conteneurs issus de la même image partagent les couches en lecture seule, économisant de l'espace disque.
- **Efficacité** : Seules les couches modifiées doivent être téléchargées ou envoyées aux registres.
</details>

<details>
<summary><strong>3. Quelle est la différence entre CMD et ENTRYPOINT dans un Dockerfile ?</strong></summary>
<br>

Les deux définissent ce qui s'exécute au démarrage d'un conteneur, mais ils se comportent différemment :

- **CMD** fournit des arguments par défaut qui peuvent être entièrement remplacés à l'exécution. Si vous exécutez `docker run myimage /bin/bash`, le CMD est remplacé.
- **ENTRYPOINT** définit l'exécutable principal qui s'exécute toujours. Les arguments à l'exécution lui sont ajoutés, pas remplacés.

Bonne pratique : Utilisez `ENTRYPOINT` pour le processus principal et `CMD` pour les arguments par défaut :

```dockerfile
ENTRYPOINT ["python", "app.py"]
CMD ["--port", "8080"]
```

Exécuter `docker run myimage --port 3000` exécutera `python app.py --port 3000`.
</details>

<details>
<summary><strong>4. Qu'est-ce qu'une construction multi-stage et pourquoi est-elle importante ?</strong></summary>
<br>

Une construction multi-stage utilise plusieurs instructions `FROM` dans un seul Dockerfile. Chaque `FROM` démarre une nouvelle étape de construction, et vous pouvez copier sélectivement des artefacts d'une étape à une autre.

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

Cela produit une image finale contenant uniquement le binaire compilé — pas d'outils de construction, pas de code source, pas de fichiers intermédiaires. Le résultat est une image considérablement plus petite (souvent 10 à 100 fois plus petite) avec une surface d'attaque réduite.
</details>

<details>
<summary><strong>5. Quelle est la différence entre COPY et ADD dans un Dockerfile ?</strong></summary>
<br>

Les deux copient des fichiers du contexte de construction dans l'image, mais `ADD` a des fonctionnalités supplémentaires :
- `ADD` peut extraire automatiquement les archives `.tar` locales.
- `ADD` peut télécharger des fichiers depuis des URLs.

Cependant, les bonnes pratiques Docker recommandent d'utiliser `COPY` dans presque tous les cas car c'est explicite et prévisible. Utilisez `ADD` uniquement lorsque vous avez spécifiquement besoin de l'extraction tar. N'utilisez jamais `ADD` pour télécharger des fichiers — utilisez `RUN curl` ou `RUN wget` à la place, afin que la couche de téléchargement puisse être mise en cache correctement.
</details>

## Réseau

<details>
<summary><strong>6. Expliquez les modes réseau de Docker (bridge, host, none, overlay).</strong></summary>
<br>

- **Bridge** (par défaut) : Crée un réseau interne privé sur l'hôte. Les conteneurs sur le même bridge peuvent communiquer par IP ou nom de conteneur. Le trafic vers l'extérieur nécessite un mappage de ports (`-p`).
- **Host** : Supprime l'isolation réseau. Le conteneur partage directement la pile réseau de l'hôte. Pas de mappage de ports nécessaire, mais pas d'isolation non plus. Utile pour les applications critiques en termes de performances.
- **None** : Aucun réseau. Le conteneur n'a qu'une interface loopback. Utilisé pour les travaux par lots ou les charges de travail sensibles à la sécurité.
- **Overlay** : S'étend sur plusieurs hôtes Docker (utilisé dans Swarm/Kubernetes). Les conteneurs sur différentes machines peuvent communiquer comme s'ils étaient sur le même réseau, en utilisant le tunneling VXLAN.
</details>

<details>
<summary><strong>7. Comment fonctionne la communication entre conteneurs ?</strong></summary>
<br>

Sur un réseau bridge défini par l'utilisateur, les conteneurs peuvent se joindre **par nom de conteneur** via le résolveur DNS intégré de Docker. Le serveur DNS fonctionne à l'adresse `127.0.0.11` à l'intérieur de chaque conteneur.

Sur le réseau bridge par défaut, la résolution DNS **n'est pas** disponible — les conteneurs ne peuvent communiquer que par adresse IP, ce qui n'est pas fiable car les IPs sont attribuées dynamiquement.

Bonne pratique : Créez toujours un réseau bridge personnalisé (`docker network create mynet`) et attachez-y les conteneurs. Ne comptez jamais sur le bridge par défaut pour la communication inter-conteneurs.
</details>

<details>
<summary><strong>8. Quelle est la différence entre EXPOSE et la publication d'un port ?</strong></summary>
<br>

`EXPOSE` dans un Dockerfile est purement de la **documentation** — il indique à quiconque lit le Dockerfile que l'application écoute sur un port spécifique. Il N'ouvre NI ne mappe réellement le port.

Publier un port (`-p 8080:80`) crée effectivement une règle réseau qui mappe un port de l'hôte vers un port du conteneur, rendant le service accessible depuis l'extérieur du conteneur.

Vous pouvez publier des ports qui ne sont pas dans la directive `EXPOSE`, et `EXPOSE` seul ne fait rien sans `-p`.
</details>

## Volumes et Stockage

<details>
<summary><strong>9. Quels sont les trois types de montages Docker ?</strong></summary>
<br>

1. **Volumes** (`docker volume create`) : Gérés par Docker, stockés dans `/var/lib/docker/volumes/`. Idéaux pour les données persistantes (bases de données). Survivent à la suppression du conteneur. Portables entre hôtes.
2. **Bind mounts** (`-v /host/path:/container/path`) : Mappent un répertoire spécifique de l'hôte dans le conteneur. Le chemin de l'hôte doit exister. Idéaux pour le développement (rechargement de code en direct). Non portables.
3. **Montages tmpfs** (`--tmpfs /tmp`) : Stockés uniquement dans la mémoire de l'hôte. Jamais écrits sur disque. Idéaux pour les données sensibles qui ne doivent pas persister (secrets, jetons de session).
</details>

<details>
<summary><strong>10. Comment persister les données d'un conteneur de base de données ?</strong></summary>
<br>

Utilisez un **volume nommé** monté dans le répertoire de données de la base de données :

```bash
docker volume create pgdata
docker run -d -v pgdata:/var/lib/postgresql/data postgres:16
```

Les données survivent aux redémarrages et suppressions du conteneur. Lors de la mise à jour de la version de la base de données, arrêtez l'ancien conteneur, démarrez-en un nouveau avec le même volume et laissez la nouvelle version gérer la migration des données.

N'utilisez jamais les bind mounts pour les bases de données en production — les volumes ont de meilleures performances d'E/S et sont gérés par le driver de stockage de Docker.
</details>

## Sécurité

<details>
<summary><strong>11. Comment sécuriser un conteneur Docker en production ?</strong></summary>
<br>

Pratiques clés de renforcement :
- **Exécuter en non-root** : Utilisez la directive `USER` dans le Dockerfile. N'exécutez jamais les processus applicatifs en root.
- **Utiliser des images de base minimales** : `alpine`, `distroless` ou `scratch` au lieu de `ubuntu`.
- **Supprimer les capabilities** : Utilisez `--cap-drop ALL --cap-add <uniquement-nécessaires>`.
- **Système de fichiers en lecture seule** : Utilisez `--read-only` et montez uniquement des chemins spécifiques en écriture.
- **Pas de nouveaux privilèges** : Utilisez `--security-opt=no-new-privileges`.
- **Scanner les images** : Utilisez `docker scout`, Trivy ou Snyk pour détecter les vulnérabilités dans les images de base et les dépendances.
- **Signer les images** : Utilisez Docker Content Trust (`DOCKER_CONTENT_TRUST=1`) pour vérifier l'authenticité des images.
- **Limiter les ressources** : Utilisez `--memory`, `--cpus` pour prévenir l'épuisement des ressources.
</details>

<details>
<summary><strong>12. Qu'est-ce que le mode rootless de Docker ?</strong></summary>
<br>

Le mode rootless de Docker exécute le daemon Docker et les conteneurs entièrement dans un namespace utilisateur, sans nécessiter de privilèges root sur l'hôte. Cela élimine la principale préoccupation de sécurité avec Docker : le daemon s'exécute en root, et une évasion de conteneur signifie un accès root à l'hôte.

En mode rootless, même si un attaquant s'échappe du conteneur, il n'obtient que les privilèges de l'utilisateur non privilégié qui exécute Docker. Le compromis est que certaines fonctionnalités (comme la liaison aux ports inférieurs à 1024) nécessitent une configuration supplémentaire.
</details>

## Docker Compose et Orchestration

<details>
<summary><strong>13. Quelle est la différence entre docker-compose up et docker-compose run ?</strong></summary>
<br>

- `docker compose up` : Démarre **tous** les services définis dans `docker-compose.yml`, crée les réseaux/volumes et respecte l'ordre de `depends_on`. Typiquement utilisé pour démarrer l'ensemble de la pile.
- `docker compose run <service> <commande>` : Démarre un **seul** service avec une commande ponctuelle. Ne démarre pas les services dépendants par défaut (utilisez `--service-ports` pour mapper les ports, `--rm` pour nettoyer). Utilisé pour exécuter des migrations, tests ou tâches d'administration.
</details>

<details>
<summary><strong>14. Comment fonctionne depends_on et quelles sont ses limitations ?</strong></summary>
<br>

`depends_on` contrôle l'**ordre de démarrage** — il s'assure que le service A démarre avant le service B. Cependant, il attend seulement que le conteneur **démarre**, pas que l'application à l'intérieur soit **prête**.

Par exemple, un conteneur de base de données peut démarrer en quelques secondes, mais PostgreSQL a besoin de temps supplémentaire pour s'initialiser. Votre conteneur d'application démarrera et échouera immédiatement à se connecter.

Solution : Utilisez `depends_on` avec une `condition` et un health check :

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
<summary><strong>15. Quand choisiriez-vous Docker Swarm plutôt que Kubernetes ?</strong></summary>
<br>

**Docker Swarm** : Intégré à Docker, aucune configuration supplémentaire. Idéal pour les déploiements petits à moyens où la simplicité compte. Utilise les mêmes fichiers Docker Compose. Écosystème et communauté limités par rapport à Kubernetes. Adapté aux équipes qui n'ont pas d'ingénieurs de plateforme dédiés.

**Kubernetes** : Standard de l'industrie pour l'orchestration de conteneurs à grande échelle. Supporte l'auto-scaling, les mises à jour progressives, le service mesh, les custom resource definitions et un écosystème massif (Helm, Istio, ArgoCD). Complexité et courbe d'apprentissage plus élevées. Nécessaire pour les déploiements à grande échelle, multi-équipes et multi-cloud.

Règle de base : Si vous avez moins de 20 services et une petite équipe, Swarm est suffisant. Au-delà, Kubernetes vaut l'investissement.
</details>

## Production et Dépannage

<details>
<summary><strong>16. Comment réduire la taille d'une image Docker ?</strong></summary>
<br>

1. **Utiliser des constructions multi-stage** — gardez les outils de construction hors de l'image finale.
2. **Utiliser des images de base minimales** — `alpine` (~5Mo) au lieu de `ubuntu` (~75Mo).
3. **Combiner les commandes RUN** — chaque `RUN` crée une couche. Chaînez les commandes avec `&&` et nettoyez dans la même couche.
4. **Utiliser .dockerignore** — excluez `node_modules`, `.git`, fichiers de test, documentation du contexte de construction.
5. **Ordonner les couches par fréquence de modification** — placez les couches rarement modifiées (dépendances) avant les couches fréquemment modifiées (code source) pour maximiser les hits de cache.
</details>

<details>
<summary><strong>17. Un conteneur redémarre sans cesse. Comment le déboguer ?</strong></summary>
<br>

Approche étape par étape :
1. `docker ps -a` — vérifiez le code de sortie. Code 137 = tué par OOM. Code 1 = erreur de l'application.
2. `docker logs <container>` — lisez les journaux de l'application pour les traces de pile ou messages d'erreur.
3. `docker inspect <container>` — vérifiez `State.OOMKilled`, les limites de ressources et les variables d'environnement.
4. `docker run -it --entrypoint /bin/sh <image>` — démarrez un shell interactif pour déboguer l'environnement manuellement.
5. `docker stats` — vérifiez si le conteneur atteint les limites de mémoire ou CPU.
6. Vérifiez `docker events` — cherchez les signaux de kill ou événements OOM du daemon.
</details>

<details>
<summary><strong>18. Quelle est la différence entre docker stop et docker kill ?</strong></summary>
<br>

- `docker stop` envoie **SIGTERM** au processus principal (PID 1) et attend une période de grâce (10 secondes par défaut). Si le processus ne se termine pas, Docker envoie SIGKILL. Cela permet à l'application d'effectuer un arrêt gracieux (fermer les connexions, vider les buffers, sauvegarder l'état).
- `docker kill` envoie **SIGKILL** immédiatement. Le processus est terminé sans aucune chance de nettoyage. À utiliser uniquement quand un conteneur ne répond plus.

Bonne pratique : Utilisez toujours `docker stop` en production. Assurez-vous que votre application gère correctement SIGTERM.
</details>

<details>
<summary><strong>19. Comment gérer les secrets dans Docker ?</strong></summary>
<br>

**Ne jamais** intégrer les secrets dans les images (ENV dans Dockerfile, COPY de fichiers .env). Ils persistent dans les couches de l'image et sont visibles avec `docker history`.

Approches par niveau de maturité :
- **Basique** : Passez les secrets via `--env-file` à l'exécution (fichier non inclus dans l'image).
- **Mieux** : Utilisez les secrets Docker Swarm ou Kubernetes secrets (montés comme fichiers, pas comme variables d'environnement).
- **Optimal** : Utilisez un gestionnaire de secrets externe (HashiCorp Vault, AWS Secrets Manager, Azure Key Vault) et injectez les secrets à l'exécution via sidecar ou init container.
</details>

<details>
<summary><strong>20. Qu'est-ce qu'un health check Docker et pourquoi est-il essentiel ?</strong></summary>
<br>

Un health check est une commande que Docker exécute périodiquement à l'intérieur du conteneur pour vérifier que l'application fonctionne réellement — pas seulement que le processus est en cours d'exécution.

```dockerfile
HEALTHCHECK --interval=30s --timeout=5s --retries=3 \
  CMD curl -f http://localhost:3000/health || exit 1
```

Sans health check, Docker sait uniquement si le processus est vivant (le PID existe). Avec un health check, Docker sait si l'application est **saine** (répond aux requêtes). C'est essentiel pour :
- **Répartiteurs de charge** : Diriger le trafic uniquement vers les conteneurs sains.
- **Orchestrateurs** : Redémarrer automatiquement les conteneurs défaillants.
- **depends_on** : Attendre la disponibilité réelle, pas seulement le démarrage du processus.
</details>
