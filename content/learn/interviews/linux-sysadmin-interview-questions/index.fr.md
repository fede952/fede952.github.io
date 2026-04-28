---
title: "Entretien Linux SysAdmin : Processus, Permissions et Réseau"
description: "20 questions essentielles d'entretien en administration de systèmes Linux pour les rôles Senior SysAdmin et DevOps. Couvre les permissions de fichiers, la gestion des processus, systemd, le réseau et le dépannage."
date: 2026-02-11
tags: ["linux", "interview", "sysadmin", "devops"]
keywords: ["linux interview questions", "red hat interview", "bash scripting questions", "linux permissions interview", "sysadmin interview questions", "linux process management", "systemd interview", "linux networking questions", "senior linux engineer", "rhcsa exam prep"]
draft: false
schema_json: >
  {
    "@context": "https://schema.org",
    "@type": "TechArticle",
    "name": "Entretien Linux SysAdmin : Processus, Permissions et Réseau",
    "description": "20 questions essentielles d'entretien en administration de systèmes Linux sur les permissions, les processus, systemd et le réseau.",
    "proficiencyLevel": "Advanced",
    "inLanguage": "fr"
  }
---

## Initialisation du Système

L'administration de systèmes Linux est la base de l'infrastructure moderne. Que vous passiez un entretien pour un rôle de SysAdmin, DevOps, SRE ou Cloud Engineer, vous serez évalué sur votre capacité à gérer les utilisateurs, dépanner les processus, configurer le réseau et sécuriser les serveurs — le tout depuis la ligne de commande. Ce guide couvre 20 questions qui séparent les candidats seniors des juniors, avec des réponses qui démontrent une véritable expérience opérationnelle.

**Besoin d'une référence rapide des commandes ?** Gardez notre [Cheatsheet Linux SysAdmin](/cheatsheets/linux-sysadmin-permissions/) ouvert pendant votre préparation.

---

## Permissions et Propriété des Fichiers

<details>
<summary><strong>1. Expliquez le modèle de permissions Linux (rwx, notation octale, bits spéciaux).</strong></summary>
<br>

Chaque fichier a trois niveaux de permissions : **Propriétaire**, **Groupe**, **Autres**. Chaque niveau peut avoir **Lecture (r=4)**, **Écriture (w=2)**, **Exécution (x=1)**.

La notation octale combine ces valeurs : `chmod 755` = rwxr-xr-x (propriétaire : tous les droits, groupe/autres : lecture+exécution).

**Bits spéciaux** :
- **SUID (4000)** : Le fichier s'exécute en tant que propriétaire du fichier, pas en tant qu'utilisateur qui le lance. Exemple : `/usr/bin/passwd` s'exécute en tant que root pour que les utilisateurs puissent changer leur propre mot de passe.
- **SGID (2000)** : Sur les fichiers, s'exécute en tant que groupe propriétaire. Sur les répertoires, les nouveaux fichiers héritent du groupe du répertoire.
- **Sticky bit (1000)** : Sur les répertoires, seul le propriétaire du fichier peut supprimer ses fichiers. Exemple classique : `/tmp`.
</details>

<details>
<summary><strong>2. Quelle est la différence entre les liens physiques et les liens symboliques ?</strong></summary>
<br>

- **Lien physique** : Une référence directe à l'inode (les données réelles sur le disque). Plusieurs liens physiques vers le même fichier partagent le même numéro d'inode. La suppression d'un lien physique n'affecte pas les autres — les données persistent jusqu'à ce que tous les liens physiques soient supprimés. Ne peut pas traverser les limites du système de fichiers. Ne peut pas lier vers des répertoires.
- **Lien symbolique (symlink)** : Un pointeur vers un chemin de fichier (comme un raccourci). Possède son propre inode. Si le fichier cible est supprimé, le symlink devient un lien pendant. Peut traverser les systèmes de fichiers. Peut lier vers des répertoires.

Utilisez `ls -li` pour voir les numéros d'inode et confirmer les relations entre liens physiques.
</details>

<details>
<summary><strong>3. Un développeur ne peut pas écrire dans un répertoire partagé. Comment diagnostiquez-vous et résolvez-vous le problème ?</strong></summary>
<br>

Étapes de diagnostic :
1. `ls -la /shared/` — vérifier la propriété et les permissions.
2. `id developer` — vérifier à quels groupes l'utilisateur appartient.
3. `getfacl /shared/` — vérifier les ACLs qui pourraient outrepasser les permissions standard.

Solutions courantes :
- Ajouter l'utilisateur au groupe du répertoire : `sudo usermod -aG devteam developer`.
- Définir le SGID sur le répertoire pour que les nouveaux fichiers héritent du groupe : `chmod g+s /shared/`.
- Si des ACLs sont nécessaires : `setfacl -m u:developer:rwx /shared/`.
- S'assurer que l'umask ne bloque pas l'écriture du groupe (vérifier avec la commande `umask`).
</details>

<details>
<summary><strong>4. Qu'est-ce que umask et comment affecte-t-il la création de fichiers ?</strong></summary>
<br>

`umask` définit les permissions par défaut **retirées** des nouveaux fichiers et répertoires. C'est un masque de bits soustrait des permissions maximales.

- Maximum par défaut pour les fichiers : 666 (pas d'exécution par défaut).
- Maximum par défaut pour les répertoires : 777.
- Avec `umask 022` : les fichiers obtiennent 644 (rw-r--r--), les répertoires obtiennent 755 (rwxr-xr-x).
- Avec `umask 077` : les fichiers obtiennent 600 (rw-------), les répertoires obtiennent 700 (rwx------).

Défini au niveau système dans `/etc/profile` ou par utilisateur dans `~/.bashrc`. Critique pour la sécurité — un umask trop permissif peut exposer des fichiers sensibles à des utilisateurs non autorisés.
</details>

## Gestion des Processus

<details>
<summary><strong>5. Expliquez la différence entre un processus, un thread et un démon.</strong></summary>
<br>

- **Processus** : Une instance d'un programme en exécution avec son propre espace mémoire, PID, descripteurs de fichiers et environnement. Créé par `fork()` ou `exec()`.
- **Thread** : Une unité d'exécution légère au sein d'un processus. Les threads partagent le même espace mémoire et les descripteurs de fichiers mais ont leur propre pile et registres. Plus rapides à créer que les processus.
- **Démon** : Un processus d'arrière-plan qui s'exécute sans terminal de contrôle. Typiquement démarré au démarrage, il s'exécute en continu et fournit un service (sshd, nginx, cron). Conventionnellement nommé avec le suffixe `d`.
</details>

<details>
<summary><strong>6. Que sont les processus zombies et comment les gérez-vous ?</strong></summary>
<br>

Un **zombie** est un processus qui a terminé son exécution mais a toujours une entrée dans la table des processus car son parent n'a pas appelé `wait()` pour lire son code de sortie. Il ne consomme aucune ressource sauf un emplacement PID.

Identifier les zombies : `ps aux | grep Z` — ils affichent le statut `Z` (defunct).

Vous **ne pouvez pas** tuer un zombie — il est déjà mort. Pour le supprimer :
1. Envoyer `SIGCHLD` au processus parent : `kill -s SIGCHLD <parent_pid>`.
2. Si le parent l'ignore, tuer le processus parent rendra le zombie orphelin, qui sera adopté par `init` (PID 1). Init appelle automatiquement `wait()` et le nettoie.

Un grand nombre de zombies indique généralement un processus parent défectueux qui ne récupère pas ses enfants.
</details>

<details>
<summary><strong>7. Expliquez les signaux Linux. Que sont SIGTERM, SIGKILL et SIGHUP ?</strong></summary>
<br>

Les signaux sont des interruptions logicielles envoyées aux processus :

- **SIGTERM (15)** : Demande de terminaison polie. Le processus peut l'intercepter, nettoyer les ressources et quitter proprement. C'est ce que `kill <pid>` envoie par défaut.
- **SIGKILL (9)** : Terminaison forcée. Ne peut être intercepté, bloqué ni ignoré. Le noyau termine le processus immédiatement. À utiliser uniquement en dernier recours — aucun nettoyage possible.
- **SIGHUP (1)** : Historiquement "raccroché". De nombreux démons (nginx, Apache) rechargent leur configuration lorsqu'ils reçoivent SIGHUP, au lieu de redémarrer.
- **SIGINT (2)** : Interruption, envoyé par Ctrl+C.
- **SIGSTOP/SIGCONT (19/18)** : Suspendre et reprendre un processus.
</details>

<details>
<summary><strong>8. Comment trouvez-vous et tuez-vous un processus qui consomme trop de CPU ?</strong></summary>
<br>

1. Identifier le processus : `top -o %CPU` ou `ps aux --sort=-%cpu | head -10`.
2. Obtenir des détails : `ls -l /proc/<pid>/exe` pour voir le binaire réel.
3. Vérifier ce qu'il fait : `strace -p <pid>` pour les appels système, `lsof -p <pid>` pour les fichiers ouverts.
4. Arrêt gracieux : `kill <pid>` (SIGTERM) — permettre le nettoyage.
5. Arrêt forcé : `kill -9 <pid>` (SIGKILL) — uniquement si SIGTERM échoue.
6. Prévenir la récurrence : Si géré par systemd, définir `CPUQuota=50%` dans le fichier unit du service.
</details>

## Systemd et Services

<details>
<summary><strong>9. Qu'est-ce que systemd et en quoi diffère-t-il de SysVinit ?</strong></summary>
<br>

**SysVinit** : Processus de démarrage séquentiel utilisant des scripts shell dans `/etc/init.d/`. Les services démarrent les uns après les autres dans un niveau d'exécution défini. Temps de démarrage lents. Simple mais gestion limitée des dépendances.

**systemd** : Processus de démarrage parallèle utilisant des fichiers unit. Supporte les dépendances, l'activation par socket, le démarrage de services à la demande, les cgroups pour le contrôle des ressources et journald pour la journalisation. Démarrage beaucoup plus rapide. Gère les services, les timers, les montages, les sockets et les targets.

systemd est le système init par défaut sur RHEL, Ubuntu, Debian, Fedora, SUSE et Arch.
</details>

<details>
<summary><strong>10. Comment créez-vous un service systemd personnalisé ?</strong></summary>
<br>

Créez un fichier unit dans `/etc/systemd/system/myapp.service` :

```ini
[Unit]
Description=My Application
After=network.target

[Service]
Type=simple
User=deploy
WorkingDirectory=/opt/myapp
ExecStart=/opt/myapp/bin/server
Restart=on-failure
RestartSec=5

[Install]
WantedBy=multi-user.target
```

Puis : `sudo systemctl daemon-reload && sudo systemctl enable --now myapp`.

Valeurs clés de `Type` : `simple` (par défaut, le processus principal s'exécute au premier plan), `forking` (le processus fait un fork en arrière-plan, nécessite `PIDFile`), `oneshot` (s'exécute une fois et se termine), `notify` (le processus signale sa disponibilité via sd_notify).
</details>

<details>
<summary><strong>11. Comment analysez-vous les performances de démarrage avec systemd ?</strong></summary>
<br>

- `systemd-analyze` — temps total de démarrage.
- `systemd-analyze blame` — liste des services triés par temps de démarrage.
- `systemd-analyze critical-chain` — arbre du chemin critique de démarrage.
- `systemd-analyze plot > boot.svg` — générer une chronologie visuelle de la séquence de démarrage.
- `journalctl -b -p err` — erreurs du démarrage actuel.

Pour accélérer le démarrage : désactiver les services inutiles (`systemctl disable`), passer les services à l'activation par socket (démarrage à la demande) et identifier les services lents à partir de la sortie blame.
</details>

## Réseau

<details>
<summary><strong>12. Expliquez le three-way handshake TCP.</strong></summary>
<br>

1. **SYN** : Le client envoie un paquet SYN au serveur avec un numéro de séquence initial.
2. **SYN-ACK** : Le serveur répond avec SYN-ACK, accusant réception du SYN du client et envoyant son propre numéro de séquence.
3. **ACK** : Le client envoie un ACK confirmant le numéro de séquence du serveur. La connexion est établie.

La déconnexion utilise un handshake à quatre voies : FIN → ACK → FIN → ACK (chaque côté ferme indépendamment sa moitié de la connexion).

Débogage avec : `ss -tuln` (ports en écoute), `ss -tulnp` (avec noms des processus), `tcpdump -i eth0 port 80` (capture de paquets).
</details>

<details>
<summary><strong>13. Quelle est la différence entre TCP et UDP ?</strong></summary>
<br>

- **TCP** (Transmission Control Protocol) : Orienté connexion, fiable, livraison ordonnée. Utilise handshake, accusés de réception, retransmissions. Overhead plus élevé. Utilisé pour HTTP, SSH, FTP, bases de données.
- **UDP** (User Datagram Protocol) : Sans connexion, non fiable, pas d'ordre garanti. Pas de handshake, pas d'accusés de réception. Overhead plus faible, latence moindre. Utilisé pour DNS, DHCP, VoIP, streaming, gaming.

Point clé : "Non fiable" ne signifie pas mauvais — cela signifie que l'application gère la fiabilité si nécessaire. DNS utilise UDP car les requêtes sont petites et rapides ; si une réponse est perdue, le client la renvoie simplement.
</details>

<details>
<summary><strong>14. Un serveur ne peut pas atteindre une IP externe. Comment dépannez-vous ?</strong></summary>
<br>

Approche couche par couche :
1. **L1 - Physique** : `ip link show` — l'interface est-elle active ?
2. **L2 - Liaison de données** : `ip neighbor show` — la table ARP est-elle peuplée ?
3. **L3 - Réseau** : `ip route show` — y a-t-il une passerelle par défaut ? `ping <gateway>` — pouvez-vous l'atteindre ?
4. **L3 - Externe** : `ping 8.8.8.8` — pouvez-vous atteindre internet par IP ?
5. **L7 - DNS** : `nslookup google.com` — la résolution DNS fonctionne-t-elle ? Vérifier `/etc/resolv.conf`.
6. **Pare-feu** : `iptables -L -n` ou `nft list ruleset` — les connexions sortantes sont-elles bloquées ?
7. **Trace de route** : `traceroute 8.8.8.8` — où le chemin s'interrompt-il ?
</details>

## Stockage et Systèmes de Fichiers

<details>
<summary><strong>15. Qu'est-ce qu'un inode ?</strong></summary>
<br>

Un inode est une structure de données qui stocke les métadonnées d'un fichier : permissions, propriété, taille, horodatages et pointeurs vers les blocs de données sur le disque. Chaque fichier et répertoire possède un inode.

Point crucial : le **nom du fichier N'EST PAS stocké dans l'inode** — il est stocké dans l'entrée du répertoire, qui associe un nom à un numéro d'inode. C'est pourquoi les liens physiques fonctionnent : plusieurs entrées de répertoire peuvent pointer vers le même inode.

Manquer d'inodes (même avec de l'espace disque libre) empêche la création de nouveaux fichiers. Vérifier avec `df -i`. Cause courante : des millions de petits fichiers (files d'attente de courrier, répertoires de cache).
</details>

<details>
<summary><strong>16. Comment étendez-vous un volume logique LVM sans temps d'arrêt ?</strong></summary>
<br>

1. Vérifier l'espace disponible : `vgdisplay` — chercher les PE (physical extents) libres.
2. S'il n'y a pas d'espace libre, ajouter un nouveau disque physique : `pvcreate /dev/sdb && vgextend myvg /dev/sdb`.
3. Étendre le volume logique : `lvextend -L +10G /dev/myvg/mylv`.
4. Redimensionner le système de fichiers (en ligne pour ext4/XFS) :
   - ext4 : `resize2fs /dev/myvg/mylv`
   - XFS : `xfs_growfs /mountpoint`

Pas de démontage nécessaire. Pas de temps d'arrêt. C'est l'un des principaux avantages de LVM par rapport aux partitions brutes.
</details>

## Sécurité et Durcissement

<details>
<summary><strong>17. Quelle est la différence entre su, sudo et sudoers ?</strong></summary>
<br>

- **su** (switch user) : Change complètement vers un autre utilisateur. `su -` charge l'environnement de l'utilisateur cible. Nécessite le mot de passe de l'utilisateur cible.
- **sudo** (superuser do) : Exécute une seule commande en tant qu'un autre utilisateur (généralement root). Nécessite le mot de passe de l'**appelant**. Fournit un journal d'audit de qui a exécuté quoi.
- **sudoers** (`/etc/sudoers`) : Fichier de configuration qui définit qui peut utiliser sudo et quelles commandes ils peuvent exécuter. Modifié en toute sécurité avec `visudo` (validation de syntaxe).

Bonne pratique : Désactiver la connexion directe en tant que root (`PermitRootLogin no` dans sshd_config). Donner plutôt l'accès sudo aux administrateurs — cela fournit la traçabilité (enregistre qui a fait quoi) et un contrôle granulaire.
</details>

<details>
<summary><strong>18. Comment durcissez-vous un serveur SSH ?</strong></summary>
<br>

Modifications essentielles dans `/etc/ssh/sshd_config` :
- `PermitRootLogin no` — empêcher la connexion directe en tant que root.
- `PasswordAuthentication no` — forcer l'authentification par clé.
- `PubkeyAuthentication yes` — activer les clés SSH.
- `Port 2222` — changer du port par défaut (réduit les scans automatisés).
- `MaxAuthTries 3` — limiter les tentatives d'authentification.
- `AllowUsers deploy admin` — liste blanche d'utilisateurs spécifiques.
- `ClientAliveInterval 300` — déconnecter les sessions inactives.
- Installer `fail2ban` — bannir automatiquement les IPs après des tentatives de connexion échouées.
</details>

## Scripting et Automatisation

<details>
<summary><strong>19. Quelle est la différence entre $?, $$, $! et $@ en Bash ?</strong></summary>
<br>

- **$?** — Code de sortie de la dernière commande (0 = succès, non-zéro = échec).
- **$$** — PID du shell actuel.
- **$!** — PID du dernier processus en arrière-plan.
- **$@** — Tous les arguments passés au script (chacun comme un mot séparé).
- **$#** — Nombre d'arguments.
- **$0** — Nom du script lui-même.
- **$1, $2, ...** — Arguments positionnels individuels.

Motif courant : `command && echo "success" || echo "fail"` utilise `$?` implicitement.
</details>

<details>
<summary><strong>20. Écrivez un one-liner pour trouver tous les fichiers de plus de 100 Mo modifiés dans les 7 derniers jours.</strong></summary>
<br>

```bash
find / -type f -size +100M -mtime -7 -exec ls -lh {} \; 2>/dev/null
```

Décomposition :
- `find /` — recherche depuis la racine.
- `-type f` — fichiers uniquement (pas les répertoires).
- `-size +100M` — plus de 100 mégaoctets.
- `-mtime -7` — modifiés dans les 7 derniers jours.
- `-exec ls -lh {} \;` — afficher la taille en format lisible pour chaque résultat.
- `2>/dev/null` — supprimer les erreurs de permission refusée.

Alternative avec tri : `find / -type f -size +100M -mtime -7 -printf '%s %p\n' 2>/dev/null | sort -rn | head -20`.
</details>
