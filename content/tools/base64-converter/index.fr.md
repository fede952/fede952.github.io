---
title: "Encoder et Décoder en Base64 (UTF-8)"
description: "Encodez du texte en Base64 ou décodez du Base64 et du Base64URL en texte, avec prise en charge UTF-8 des accents et emoji. Gratuit, immédiat, local."
intro: "Convertissez du texte en **Base64** et inversement. L'encodage est sûr pour l'UTF-8, et le décodage accepte aussi la variante **Base64URL** utilisée par les JWT et les API web, avec ou sans padding `=`. Rien de ce que vous collez ne quitte cette page."
date: 2026-02-03
lastmod: 2026-10-24
reviewed: false
keywords: ["encoder base64", "décoder base64", "base64 decoder", "base64 en ligne", "décoder base64url", "base64 en texte", "base64 utf-8", "convertisseur base64"]
tags: ["encodage", "outils-développeur", "base64", "outil"]
app_category: "DeveloperApplication"
tool_partial: "base64-converter"
howto:
  - "Saisissez ou collez dans **Texte d’entrée** : du texte à encoder, ou une chaîne Base64 à décoder."
  - "Cliquez sur **Encoder en Base64** pour transformer le texte en Base64. Accents, alphabets non latins et emoji sont encodés en UTF-8."
  - "Cliquez sur **Décoder le Base64** pour retrouver le texte. Le Base64 standard, le Base64URL (`-` et `_`), le padding manquant et les retours à la ligne sont acceptés."
  - "Lisez le résultat dans **Résultat** et cliquez sur **Copier** pour le placer dans le presse-papiers."
  - "Si les octets décodés ne forment pas un UTF-8 valide, l'outil vous le signale : il s'agit probablement de données binaires (une image, un fichier compressé ou une clé) et non de texte."
faq:
  - q: "À quoi sert le Base64 ?"
    a: "Le Base64 représente des données binaires avec 64 caractères ASCII imprimables, pour qu'elles circulent dans des systèmes qui ne gèrent que du texte : pièces jointes d'e-mail (MIME), data URL en HTML et CSS, payloads JSON, en-têtes d'authentification HTTP Basic, Secrets Kubernetes et les trois parties d'un JSON Web Token."
  - q: "Le Base64 est-il un chiffrement ?"
    a: "Non. C'est un encodage sans clé : n'importe qui peut le décoder instantanément, comme le montre cette page. N'utilisez jamais le Base64 pour cacher des mots de passe ou des secrets ; les Secrets Kubernetes, par exemple, ne sont qu'encodés en Base64, pas chiffrés, sauf si vous activez le chiffrement au repos."
  - q: "Quelle différence entre Base64 et Base64URL ?"
    a: "Le Base64URL (RFC 4648, section 5) remplace `+` par `-` et `/` par `_` pour que le résultat soit sûr dans les URL et les noms de fichiers, et supprime généralement le padding `=`. Les JWT et de nombreuses API l'utilisent. Cet outil décode les deux ; à l'encodage, il produit du Base64 standard."
  - q: "Pourquoi mon texte décodé est-il illisible ?"
    a: "Soit l'entrée n'était pas du texte au départ (une image ou un flux gzip, par exemple), soit le texte d'origine a été encodé avec un autre jeu de caractères, comme Latin-1 au lieu d'UTF-8. L'outil décode en UTF-8 et vous prévient quand les octets ne forment pas un UTF-8 valide."
  - q: "Pourquoi le Base64 est-il environ un tiers plus lourd que l'original ?"
    a: "Chaque groupe de 3 octets devient 4 caractères Base64, car chaque caractère porte 6 bits (2⁶ = 64). Cela représente 33 % de surcoût, plus jusqu'à deux caractères `=` de padding à la fin. Une image de 30 Ko devient une data URL de 40 Ko."
  - q: "Le texte collé est-il envoyé quelque part ?"
    a: "Non. L'encodage et le décodage utilisent les fonctions intégrées du navigateur `btoa`, `atob`, `TextEncoder` et `TextDecoder`, dans cette page. Rien n'est envoyé ni conservé."
---

## Comment ça marche

### Encodage

La fonction `btoa()` de JavaScript ne comprend que les caractères de la plage Latin-1 : l'appeler directement sur `"Garçon €"` déclenche une erreur. L'outil l'évite en encodant correctement :

1. `TextEncoder` convertit le texte en **octets UTF-8** : `ç` devient `C3 A7`, `€` devient `E2 82 AC`.
2. Chaque octet est transformé en caractère d'un octet, puis `btoa()` convertit cette chaîne d'octets en Base64.

Le Base64 travaille par groupes de **3 octets = 24 bits**, découpés en quatre valeurs de 6 bits, chacune associée à un caractère de l'alphabet `A–Z a–z 0–9 + /`. Quand la longueur de l'entrée n'est pas un multiple de 3, le dernier groupe est complété par `=` :

| Texte | Octets UTF-8 | Base64 |
|---|---|---|
| `Man` | `4D 61 6E` | `TWFu` |
| `Ma` | `4D 61` | `TWE=` |
| `M` | `4D` | `TQ==` |
| `é` | `C3 A9` | `w6k=` |

### Décodage

Le décodage inverse le processus avec une certaine tolérance pour les entrées réelles :

- Tous les espaces et retours à la ligne sont supprimés (le MIME coupe le Base64 tous les 76 caractères).
- Les caractères **Base64URL** `-` et `_` redeviennent `+` et `/`, et le padding `=` manquant est rétabli : vous pouvez coller un segment de JWT tel quel.
- `atob()` transforme le Base64 en octets et `TextDecoder` avec `fatal: true` les interprète comme de l'UTF-8. S'ils ne forment pas un UTF-8 valide, l'outil affiche malgré tout un décodage approximatif, mais prévient qu'il s'agit probablement de données binaires.
- Une chaîne dont la longueur divisée par 4 laisse un reste de 1 ne peut jamais être du Base64 valide ; elle est rejetée avec un message clair.

## Cas d'usage

- **Lire un JWT à la main.** Collez le segment central d'un token pour voir ses claims JSON (pour vérifier la signature, utilisez JWT Inspector).
- **Kubernetes et Docker.** Décodez les valeurs d'un manifeste Secret, ou encodez une valeur avant de la placer dans `data:`.
- **Authentification HTTP Basic.** Décodez un en-tête `Authorization: Basic …` pour voir le `utilisateur:motdepasse` qu'il contient, ou construisez-en un pour une requête de test.
- **Data URL et e-mail.** Inspectez des URI `data:` et des parties MIME dans la source brute d'un e-mail.
- **Déboguer des API.** Beaucoup d'API encodent en Base64 des champs binaires ou du JSON imbriqué : décodez-les pour voir ce qui a réellement été envoyé.
