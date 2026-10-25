---
title: "Chiffre de César : Chiffrer et Déchiffrer"
description: "Chiffrez et déchiffrez du texte avec le chiffre de César, avec tout décalage de 1 à 25, ROT13 compris. Découvrez comment il marche et comment on le casse."
intro: "Décalez chaque lettre de votre texte d'un nombre fixe de positions dans l'alphabet, le chiffrement qu'utilisait Jules César. Choisissez un décalage de 1 à 25 (13 donne le **ROT13**), puis chiffrez ou déchiffrez. Un classique des énigmes, des CTF et de l'apprentissage des limites des chiffrements simples."
date: 2026-02-03
lastmod: 2026-10-24
reviewed: false
keywords: ["chiffre de césar", "déchiffrer code césar", "code césar", "rot13", "chiffrement par décalage", "chiffrer un texte", "cryptographie classique", "chiffre de césar en ligne"]
tags: ["cryptographie", "chiffrement", "ctf", "outil"]
app_category: "EducationalApplication"
tool_partial: "caesar-cipher"
howto:
  - "Saisissez ou collez votre message dans **Texte d’entrée**."
  - "Réglez le **Décalage** avec le curseur (1–25). César utilisait 3 ; 13 correspond au ROT13."
  - "Cliquez sur **Chiffrer** pour décaler les lettres vers l'avant, ou sur **Déchiffrer** pour les ramener du même nombre."
  - "Lisez le résultat dans **Résultat** et cliquez sur **Copier** pour le placer dans le presse-papiers."
  - "Pour casser un message inconnu, déchiffrez-le avec chaque décalage jusqu'à voir apparaître des mots lisibles : il n'y en a que 25 à essayer."
faq:
  - q: "Comment fonctionne le chiffre de César ?"
    a: "Chaque lettre est remplacée par celle qui se trouve un nombre fixe de positions plus loin dans l'alphabet, en revenant à A après Z. Avec un décalage de 3, A devient D, B devient E et Z devient C. Pour déchiffrer, on recule du même nombre."
  - q: "Qu'est-ce que le ROT13 ?"
    a: "Le ROT13 est le chiffre de César avec un décalage de 13. L'alphabet comptant 26 lettres, l'appliquer deux fois redonne le texte d'origine : la même opération chiffre et déchiffre. Il servait sur les forums à masquer spoilers et chutes de blagues, jamais à la sécurité."
  - q: "Le chiffre de César est-il sûr ?"
    a: "Non. Il n'existe que 25 clés utiles : n'importe qui peut toutes les essayer à la main en quelques secondes. L'analyse de fréquences le casse encore plus vite : en français, la lettre la plus courante est le E, qui apparaît dans le texte chiffré décalé de la clé. Réservez-le aux jeux et à l'enseignement."
  - q: "Que deviennent les chiffres, les espaces et les lettres accentuées ?"
    a: "Ils restent inchangés. L'outil ne décale que les 26 lettres latines de base A–Z et a–z, en respectant majuscules et minuscules. Les chiffres, la ponctuation, les espaces et les lettres comme é ou ç passent tels quels."
  - q: "Comment déchiffrer un code César sans la clé ?"
    a: "Par force brute : déchiffrez avec les décalages 1 à 25 et cherchez celui qui donne un texte lisible. Pour les messages plus longs, comptez les lettres : la plus fréquente correspond généralement au E en français, et l'écart entre les deux est le décalage."
  - q: "Mon texte est-il envoyé quelque part ?"
    a: "Non. Le décalage est calculé par quelques lignes de JavaScript dans cette page et rien n'est envoyé."
---

## Comment ça marche

L'outil parcourt votre texte caractère par caractère et regarde son code :

- les majuscules `A–Z` (codes 65–90) sont décalées à l'intérieur de l'alphabet majuscule ;
- les minuscules `a–z` (codes 97–122), à l'intérieur de l'alphabet minuscule ;
- tout le reste (chiffres, espaces, ponctuation, lettres accentuées et non latines) est recopié sans changement.

Le décalage relève de l'arithmétique modulaire sur la position *p* de la lettre (0 pour A, 25 pour Z) et la clé *k* :

**chiffré = (p + k) mod 26**, et le déchiffrement utilise −k.

Comme `%` peut renvoyer un nombre négatif en JavaScript, le code calcule `((p + k) % 26 + 26) % 26`, ce qui garde le résultat entre 0 et 25 dans les deux sens. La position est ensuite reconvertie en caractère avec sa casse d'origine.

| Texte clair | Décalage 3 | Décalage 13 (ROT13) |
|---|---|---|
| `HELLO` | `KHOOR` | `URYYB` |
| `Attack at dawn` | `Dwwdfn dw gdzq` | `Nggnpx ng qnja` |
| `Zebra` | `Cheud` | `Mroen` |

### Pourquoi il se casse si facilement

Le chiffre de César a un espace de clés de 25. Un ordinateur, ou une personne patiente, essaie toutes les clés en un instant. Et comme chaque lettre correspond toujours à la même lettre, le texte chiffré conserve l'empreinte statistique de la langue : le symbole le plus fréquent d'un texte français chiffré est presque toujours un E décalé de la clé. Ces deux faiblesses, espace de clés minuscule et fréquences conservées, sont justement ce que les chiffrements modernes comme AES sont conçus pour éviter.

## Cas d'usage

- **Défis CTF et énigmes.** César et ROT13 reviennent sans cesse dans les CTF pour débutants, les escape games et le géocaching.
- **Enseigner la cryptographie.** Montrez chiffrement, clés et force brute avec un procédé réalisable sur papier, puis expliquez pourquoi il échoue.
- **Masquer des spoilers.** Le ROT13 cache toujours une chute ou une solution d'une lecture accidentelle.
- **Exercices de programmation.** Comparez votre propre implémentation à celle-ci : l'arithmétique modulaire et la gestion de la casse sont les pièges habituels.
- **Curiosité historique.** Codez un message comme les généraux romains, avec un décalage de 3.
