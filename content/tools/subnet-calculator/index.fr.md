---
title: "Calculateur de sous-réseaux IPv4/IPv6 VLSM"
description: "Calculez réseau, broadcast, plage d'hôtes, masque et wildcard de tout CIDR IPv4 ou IPv6, et découpez un bloc en sous-réseaux égaux ou VLSM."
intro: "Un **calculateur de sous-réseaux** pour IPv4 et IPv6 : saisissez une adresse avec son préfixe ou son masque et obtenez aussitôt le réseau, le broadcast, la plage d'hôtes utilisables, le masque, le wildcard et le nombre d'hôtes, avec une vue binaire. Un troisième onglet découpe un bloc en sous-réseaux égaux ou en sous-réseaux VLSM dimensionnés selon les hôtes."
date: 2026-10-25
lastmod: 2026-10-25
reviewed: false
keywords: ["calculateur sous-réseau", "calcul sous-réseau", "calculateur cidr", "calcul masque de sous-réseau", "calculateur sous-réseau ipv6", "calculateur vlsm", "masque wildcard", "calcul adresse réseau"]
tags: ["réseau", "outils-développeurs", "ipv4", "ipv6", "tool"]
app_category: "DeveloperApplication"
tool_file: "/tools/subnet-calculator/"
tool_title: "Calculateur de sous-réseaux pour IPv4, IPv6 et VLSM"
tool_height: 900
tool_sandbox: "allow-scripts allow-same-origin"
tool_allow: "clipboard-write"
howto:
  - "Dans l'onglet **IPv4**, saisissez une adresse avec un préfixe (`10.0.0.5/8`), un masque en notation décimale (`172.16.5.4 255.255.240.0`) ou un wildcard façon Cisco (`192.168.1.1 0.0.0.255`). Une adresse seule vaut `/32`."
  - "Les résultats s'affichent pendant la saisie : réseau, broadcast, premier et dernier hôte utilisables, masque, wildcard, hôtes utilisables et adresses au total, et le type d'adresse (privée, publique, CGNAT, link-local…)."
  - "Regardez le tableau **Binaire** : les bits réseau sont mis en évidence et les bits hôte atténués, pour voir exactement où le préfixe coupe l'adresse."
  - "Dans l'onglet **IPv6**, collez une adresse complète ou compressée avec un préfixe pour obtenir la forme compressée selon la RFC 5952, la forme développée, la première et la dernière adresse du préfixe et le nombre de réseaux /64 qu'il contient."
  - "Dans **Découper (VLSM)**, saisissez le bloc à découper et choisissez **En sous-réseaux égaux** (combien) ou **Selon les hôtes par sous-réseau (VLSM)** (une liste comme `100, 50, 20, 2`). Copiez une valeur avec son bouton **Copier**, ou tout le plan avec **Copier le tableau**."
faq:
  - q: "Pourquoi un /24 a-t-il 254 hôtes utilisables et non 256 ?"
    a: "Un /24 compte 256 adresses, mais la première est l'adresse réseau et la dernière l'adresse de broadcast. Aucune des deux ne peut être attribuée à un hôte, il en reste donc 254. La même règle (total moins deux) vaut pour tous les préfixes jusqu'à /30."
  - q: "Comment le calculateur traite-t-il les /31 et /32 ?"
    a: "Un /31 est traité comme une liaison point à point selon la RFC 3021 : les deux adresses sont utilisables et il n'y a pas de broadcast. Un /32 est un hôte unique, utilisé pour les loopbacks, les routes d'hôte et les règles de pare-feu. Les équipements anciens qui ne gèrent pas la RFC 3021 demandent un /30 pour une liaison."
  - q: "Qu'est-ce qu'un masque wildcard ?"
    a: "L'inverse bit à bit du masque de sous-réseau : 255.255.255.0 devient 0.0.0.255. Les ACL Cisco et les commandes network d'OSPF utilisent des wildcards, où un bit 0 signifie « doit correspondre » et un bit 1 « n'importe quelle valeur ». Vous pouvez saisir un wildcard directement dans le champ IPv4 : le calculateur le convertit en préfixe."
  - q: "Que signifie VLSM et pourquoi les plus grands sous-réseaux sont-ils placés en premier ?"
    a: "Le Variable Length Subnet Masking donne à chaque sous-réseau son propre préfixe : un LAN de 100 hôtes reçoit un /25, une liaison point à point un /31. Attribuer de la demande la plus grande à la plus petite garde chaque sous-réseau aligné sur sa frontière sans trous perdus ; les résultats sont ensuite affichés dans l'ordre de saisie."
  - q: "Pourquoi un découpage en 3 sous-réseaux en donne-t-il 4 ?"
    a: "Le découpage égal emprunte des bits d'hôte, et chaque bit double le nombre de sous-réseaux : 1 bit en donne 2, 2 bits en donnent 4. Trois sous-réseaux demandent donc 2 bits, ce qui en produit 4. Utilisez le mode VLSM pour obtenir exactement le nombre demandé, chacun dimensionné selon ses hôtes."
  - q: "Quel préfixe IPv6 utiliser pour un LAN ?"
    a: "Un /64. L'autoconfiguration sans état (SLAAC) et de nombreuses fonctions d'IPv6 supposent un identifiant d'interface de 64 bits. Un site reçoit en général un /48 ou un /56 et le découpe en /64 ; le calculateur indique combien de réseaux /64 tiennent dans le préfixe saisi."
  - q: "Ce que je saisis est-il envoyé à un serveur ?"
    a: "Non. Tous les calculs sont faits par un petit module JavaScript dans votre navigateur ; la page n'envoie aucune requête avec vos données, vous pouvez donc l'utiliser avec des plans d'adressage internes."
---

## Comment ça marche

### Arithmétique IPv4

Une adresse IPv4 est un nombre de 32 bits. Le calculateur lit les quatre octets (en refusant les valeurs supérieures à 255 et les zéros de tête ambigus comme `010`), construit le masque à partir de la longueur du préfixe en mettant à un les *n* bits de poids fort, puis effectue de simples opérations bit à bit :

- **Adresse réseau** = adresse AND masque.
- **Wildcard** = NOT masque.
- **Adresse de broadcast** = réseau OR wildcard.
- **Hôtes utilisables** = 2^(32 − préfixe) − 2, avec les deux exceptions décrites dans la FAQ : un /31 a deux adresses utilisables (RFC 3021) et un /32 une seule.

Un masque en notation décimale doit être *contigu* : des 1 suivis de 0. `255.255.240.0` est accepté comme /20, `255.0.255.0` est refusé. Si la valeur n'est pas un masque valide mais un wildcard valide (des 0 suivis de 1), elle est lue comme wildcard : `0.0.15.255` signifie donc aussi /20.

Le type d'adresse provient des registres IANA d'usage spécial : plages privées RFC 1918 (10/8, 172.16/12, 192.168/16), espace partagé pour le NAT d'opérateur (100.64/10, RFC 6598), loopback (127/8), link-local (169.254/16), les trois plages de documentation, multicast (224/4) et espace réservé.

### IPv6

Les adresses IPv6 sont des nombres de 128 bits, manipulés comme des `BigInt` JavaScript pour ne rien perdre en précision. L'analyseur accepte la forme complète, la compression `::` (une seule fois par adresse) et une fin IPv4 comme `::ffff:192.0.2.1`. La sortie suit la **RFC 5952**, la forme textuelle canonique : hexadécimal en minuscules, sans zéros de tête dans un groupe, et la plus longue suite d'au moins deux groupes nuls remplacée par `::` (celle de gauche en cas d'égalité). Un groupe nul isolé n'est jamais compressé.

Pour un préfixe, la première adresse est l'adresse AND le masque, la dernière met tous les bits hôte à un, et la taille vaut 2^(128 − préfixe). IPv6 n'a pas de broadcast, donc pas de « moins deux ».

### Découper un bloc

*En sous-réseaux égaux* ajoute ⌈log₂ n⌉ bits au préfixe et liste tous les sous-réseaux obtenus (jusqu'à 1 024 lignes). *VLSM* calcule pour chaque nombre d'hôtes le plus petit préfixe qui le contient, trie les demandes de la plus grande à la plus petite et attribue chacune à la prochaine adresse alignée sur sa taille. Si une demande ne tient plus dans l'espace restant, une erreur la nomme au lieu de produire un plan qui se chevauche.

## Cas d'usage

- **Concevoir un plan d'adressage.** Découpez un /22 pour un nouveau site en VLAN utilisateurs, voix, imprimantes et administration selon l'effectif, puis collez le tableau dans votre documentation.
- **Écrire des règles de pare-feu et des ACL.** Obtenez le réseau/préfixe ou le wildcard exact pour un groupe d'objets, et vérifiez qu'un /20 couvre bien la plage attendue.
- **Dépannage.** Deux hôtes ne se voient pas : saisissez les deux adresses avec leur masque et vérifiez qu'ils sont bien dans le même sous-réseau.
- **Réseaux cloud.** Planifiez les CIDR de VPC et de sous-réseaux sans chevauchement, en sachant que les fournisseurs réservent quelques adresses par sous-réseau en plus du réseau et du broadcast.
- **Apprentissage et examens.** Vérifiez vos exercices de subnetting pour le CCNA, Network+ ou un entretien ; la vue binaire montre pourquoi le résultat est celui-là.
