---
title: "Générateur de Hash : MD5, SHA-256, SHA-512"
description: "Générez les hashs MD5, SHA-1, SHA-256 et SHA-512 de n'importe quel texte pendant la saisie, avec UTF-8 et copie en un clic. Calculé dans votre navigateur."
intro: "Saisissez ou collez un texte et obtenez à la fois ses empreintes **MD5, SHA-1, SHA-256 et SHA-512**, mises à jour pendant la frappe. La famille SHA est calculée par la Web Crypto API de votre navigateur ; rien de ce que vous saisissez n'est envoyé."
date: 2026-02-03
lastmod: 2026-10-24
reviewed: false
keywords: ["générateur de hash", "générateur sha256", "générateur md5", "hash sha512 en ligne", "hash sha1", "texte en sha256", "calculer une somme de contrôle", "calculateur de hash en ligne"]
tags: ["cryptographie", "hash", "outils-développeur", "outil"]
app_category: "DeveloperApplication"
tool_partial: "hash-generator"
howto:
  - "Saisissez ou collez votre texte dans **Texte d’entrée**. Les quatre empreintes sont recalculées à chaque frappe."
  - "Lisez le résultat dont vous avez besoin : **MD5** (32 caractères hexadécimaux), **SHA-1** (40), **SHA-256** (64) ou **SHA-512** (128)."
  - "Cliquez sur **Copier** à côté d'une empreinte pour la placer dans le presse-papiers."
  - "Pour la comparer à une empreinte fournie, collez les deux dans un éditeur ou comparez-les caractère par caractère : un seul caractère différent signifie une entrée différente."
  - "Cliquez sur **Tout effacer** pour vider l'entrée et les résultats."
faq:
  - q: "Quel algorithme de hachage utiliser ?"
    a: "Pour les contrôles d'intégrité, les empreintes et les nouveaux projets, SHA-256 (ou SHA-512). MD5 et SHA-1 sont cassés du point de vue de la sécurité : des attaques par collision pratiques existent, ils ne doivent donc pas servir pour des signatures ou des certificats. Ils restent utilisables hors sécurité, par exemple comme clés de cache ou pour retrouver une somme de contrôle d'un ancien système."
  - q: "Puis-je hacher un mot de passe avec cet outil ?"
    a: "Vous pouvez calculer le SHA-256 de n'importe quelle chaîne, mais un simple hash SHA est la mauvaise façon de stocker des mots de passe : il est conçu pour être rapide, si bien qu'un attaquant peut tester des milliards d'essais par seconde. Les vrais systèmes utilisent une fonction de hachage de mots de passe lente et salée, comme Argon2id, bcrypt, scrypt ou PBKDF2."
  - q: "Pourquoi mon hash diffère-t-il de celui d'un autre outil ?"
    a: "C'est presque toujours l'entrée qui diffère. Vérifiez un saut de ligne final (`echo` en ajoute un ; utilisez `echo -n`), des espaces, des fins de ligne Windows `\\r\\n` ou un autre encodage. Cet outil hache exactement les caractères du champ, encodés en UTF-8."
  - q: "Puis-je calculer le hash d'un fichier ?"
    a: "Pas avec cette page : elle traite du texte. Pour les fichiers, utilisez la ligne de commande : `sha256sum fichier` sous Linux, `shasum -a 256 fichier` sous macOS ou `Get-FileHash fichier -Algorithm SHA256` dans PowerShell sous Windows."
  - q: "Peut-on inverser ou déchiffrer un hash ?"
    a: "Non. Un hash est une fonction à sens unique : il n'y a pas de clé ni de moyen de retrouver l'entrée à partir de la sortie. Les sites qui « déchiffrent le MD5 » consultent simplement des tables d'empreintes précalculées de mots courants, et c'est justement pourquoi le hachage ne protège pas les entrées courtes ou banales."
  - q: "Ce que je tape est-il envoyé à un serveur ?"
    a: "Non. SHA-1, SHA-256 et SHA-512 sont calculés avec `crypto.subtle.digest()` et MD5 avec une implémentation JavaScript, le tout dans cette page. Aucune requête réseau ne contient votre saisie."
---

## Comment ça marche

À chaque modification, l'outil lit le champ de texte, le convertit en octets avec `TextEncoder` (UTF-8 : `é` occupe deux octets, un emoji quatre) et lance quatre fonctions de hachage en parallèle avec `Promise.all` :

- **SHA-1, SHA-256 et SHA-512** passent par la **Web Crypto API** native du navigateur : `crypto.subtle.digest('SHA-256', bytes)` renvoie un `ArrayBuffer`, converti ensuite en hexadécimal minuscule.
- **MD5** ne fait pas partie de Web Crypto, car il est considéré comme cassé : il est donc calculé par une implémentation JavaScript compacte de la RFC 1321, sur les mêmes octets UTF-8.

Les résultats sont des chaînes hexadécimales dont la longueur est fixée par l'algorithme, quelle que soit la taille de l'entrée :

| Algorithme | Taille | Caractères hex | Statut |
|---|---|---|---|
| MD5 | 128 bits | 32 | Cassé (collisions depuis 2004) |
| SHA-1 | 160 bits | 40 | Cassé (collision pratique, 2017) |
| SHA-256 | 256 bits | 64 | Sûr, le choix par défaut |
| SHA-512 | 512 bits | 128 | Sûr, plus rapide sur processeur 64 bits |

Deux propriétés rendent ces fonctions utiles. Elles sont **déterministes** : la même entrée donne toujours la même empreinte, sur n'importe quelle machine. Et elles ont un **effet avalanche** : changez un caractère et environ la moitié des bits de sortie basculent, si bien que `Bonjour` et `bonjour` ont des SHA-256 sans aucun rapport. Les boutons `Copier` utilisent la Clipboard API, avec une solution de repli pour les anciens navigateurs.

### Du texte, pas des fichiers

L'entrée est le texte du champ : les empreintes ne correspondent à celles des outils en ligne de commande que si les octets sont strictement identiques. `printf 'Bonjour, le monde !' | sha256sum` et cet outil concordent ; `echo 'Bonjour, le monde !' | sha256sum` non, car `echo` ajoute un saut de ligne.

## Cas d'usage

- **Vérifier une somme de contrôle.** Beaucoup de projets publient le SHA-256 d'une chaîne de version ou d'une petite configuration : collez le texte et comparez.
- **Déboguer des signatures et des API.** Vérifiez l'empreinte qu'une API attend pour un payload, ou le SHA-256 qui entre dans une signature AWS Signature V4 ou la vérification d'un webhook.
- **Clés de cache et déduplication.** Dérivez un identifiant stable du texte d'une URL, d'une requête ou d'un document.
- **Apprendre la cryptographie.** Observez l'effet avalanche en direct, comparez les tailles d'empreintes et comprenez pourquoi MD5 et SHA-1 sont retirés pour la sécurité.
- **Retrouver des données historiques.** Recréez une valeur MD5 ou SHA-1 stockée par un ancien système pour la migrer vers quelque chose de plus solide.
