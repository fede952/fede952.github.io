---
title: "Compteur de Mots et Majuscules"
description: "Comptez mots, caractères, lignes et temps de lecture en direct ; changez la casse, retirez les doublons, nettoyez les espaces ou passez en leetspeak."
intro: "**StringMaster** est un petit atelier de texte. Collez n'importe quoi : il compte mots, caractères, lignes et temps de lecture pendant la saisie et, d'un clic, change la casse, supprime les lignes en double, nettoie les espaces ou transforme le texte en leetspeak. Le texte reste dans l'onglet de votre navigateur."
date: 2026-02-10
lastmod: 2026-10-24
reviewed: false
keywords: ["compteur de mots", "compteur de caractères", "outils texte en ligne", "convertir majuscules minuscules", "supprimer lignes en double", "supprimer espaces en ligne", "convertisseur leetspeak", "temps de lecture"]
tags: ["texte", "outils-dev", "écriture", "outil"]
app_category: "UtilitiesApplication"
tool_file: "/tools/string-master/"
tool_title: "StringMaster, outils texte"
tool_height: 750
tool_sandbox: "allow-scripts allow-same-origin"
tool_allow: "clipboard-write"
howto:
  - "Collez ou saisissez votre texte dans la zone **Entrée**. **Mots**, **Caractères**, **Lignes** et **Temps Lecture** se mettent à jour à chaque frappe."
  - "Cliquez sur **Majuscules** ou **Minuscules** pour convertir tout le texte."
  - "Cliquez sur **Suppr. Doublons** pour ne garder que la première occurrence de chaque ligne, ou sur **Suppr. Espaces** pour retirer les espaces en bout de ligne et regrouper les lignes vides."
  - "Cliquez sur **Mode Hacker** pour réécrire le texte en leetspeak (`hello` → `h3110`)."
  - "Cliquez sur **Copier** pour placer le résultat dans le presse-papiers. Les transformations remplacent le texte : copiez l'original d'abord si vous pouvez en avoir besoin."
faq:
  - q: "Comment les mots sont-ils comptés ?"
    a: "Le texte est découpé sur toute suite d'espaces blancs (espaces, tabulations, retours à la ligne) : `porte-monnaie` compte pour un mot et `p. ex. ceci` pour trois. Les langues écrites sans espaces, comme le chinois ou le japonais, donnent un mot par bloc ; utilisez plutôt le nombre de caractères."
  - q: "Les emoji et les lettres accentuées comptent-ils pour un caractère ?"
    a: "Oui. Le compteur utilise la segmentation en graphèmes du navigateur (`Intl.Segmenter`) : 👍, é et même un emoji « famille » composé de plusieurs points de code comptent une seule fois, comme à l'écran. Certaines plateformes, comme les SMS, comptent autrement (en unités UTF-16 ou en octets) et atteignent leur limite plus tôt."
  - q: "Comment le temps de lecture est-il estimé ?"
    a: "Nombre de mots divisé par 200 mots par minute, une moyenne courante pour la lecture à l'écran, arrondi au supérieur. Sous une minute, il s'affiche en secondes (`45s`), au-delà en minutes entières (`4m`). Un texte technique ou dense se lit généralement plus lentement."
  - q: "Suppr. Doublons tient-il compte de la casse ?"
    a: "Oui, et la comparaison est exacte : `Pomme`, `pomme` et `pomme ` (avec une espace finale) sont trois lignes différentes. Appliquez d'abord **Suppr. Espaces** et **Minuscules** pour une comparaison plus souple. L'ordre des premières occurrences est conservé, et les lignes vides répétées sont aussi réduites à une seule."
  - q: "Puis-je annuler une transformation ?"
    a: "Il n'y a pas de bouton Annuler et, comme le texte est remplacé par script, Ctrl+Z ne le récupère pas dans tous les navigateurs. Minuscules, Suppr. Doublons, Suppr. Espaces et Mode Hacker perdent de l'information : gardez une copie de l'original."
  - q: "Peut-on revenir en arrière depuis le leetspeak ?"
    a: "Pas de façon fiable. `i` et `l` deviennent tous deux `1`, et les chiffres déjà présents dans le texte ne se distinguent pas des lettres remplacées. Le Mode Hacker est un effet de style à sens unique, pas un encodage."
  - q: "Mon texte est-il envoyé quelque part ?"
    a: "Non. Comptages et transformations sont du simple JavaScript dans la page ; rien n'est stocké ni transmis. Vous pouvez l'utiliser sans souci pour des brouillons, des logs ou des documents internes."
---

## Comment ça marche

Chaque frappe dans la zone lance la même petite analyse :

- **Mots** = nombre de blocs non vides après découpage du texte (débarrassé de ses espaces aux extrémités) sur les espaces blancs (`/\s+/`).
- **Caractères** = nombre de grappes de graphèmes, c'est-à-dire les caractères qu'une personne compterait, via `Intl.Segmenter` ; les navigateurs sans prise en charge comptent les points de code Unicode. Espaces et retours à la ligne sont comptés.
- **Lignes** = nombre de lignes séparées par des retours à la ligne. Une zone vide affiche 0, et un retour final ajoute une dernière ligne vide.
- **Temps Lecture** = ⌈mots ÷ 200 × 60⌉ secondes, affiché en secondes sous une minute et en minutes arrondies au supérieur au-delà.

Chaque bouton applique une transformation à tout le texte, puis recompte :

| Bouton | Effet | Exemple |
|---|---|---|
| **Majuscules** | Majuscules Unicode (`toUpperCase`) | `straße` → `STRASSE` |
| **Minuscules** | Minuscules Unicode (`toLowerCase`) | `BoNjOuR` → `bonjour` |
| **Suppr. Doublons** | Garde la première copie de chaque ligne identique, dans l'ordre | `a, b, a, c` → `a, b, c` |
| **Suppr. Espaces** | Rogne chaque ligne, autorise au plus une ligne vide d'affilée, rogne les extrémités | `··texte··` → `texte` |
| **Mode Hacker** | Remplace a→4, b→8, e→3, g→9, i→1, l→1, o→0, s→5, t→7 | `get root` → `937 r007` |
| **Copier** | Copie le texte via la Clipboard API | — |

Deux détails utiles. La conversion de casse ne dépend pas de la langue : le *i* turc avec et sans point suit les règles Unicode génériques. Suppr. Espaces n'agit que sur les extrémités de ligne et les lignes vides ; les doubles espaces *à l'intérieur* d'une ligne restent, ce qui préserve l'indentation du code et les tableaux.

## Cas d'usage

- **Écrire sous contrainte.** Vérifiez dissertations, meta descriptions, résumés ou publications sociales par rapport à un plafond de mots ou de caractères pendant la rédaction.
- **Nettoyer des listes.** Collez une colonne d'e-mails, de noms d'hôte ou d'identifiants exportée d'un tableur et supprimez les doublons d'un clic ; passez d'abord en minuscules les données comme les adresses e-mail.
- **Ranger des logs et sorties collées.** Retirez les espaces de fin et tassez les lignes vides d'une sortie de terminal avant de la coller dans un ticket ou un document.
- **Normaliser des identifiants.** Passez en minuscules des tags ou des clés avant de les comparer, ou en majuscules des constantes et mots-clés SQL.
- **Texte pour le plaisir.** Transformez un pseudo, une bannière ou le nom de votre équipe CTF en leetspeak.
- **Estimer la durée d'une intervention.** Le temps de lecture donne un ordre de grandeur pour un script ; à l'oral on va moins vite, généralement 130 à 150 mots par minute.

Pour encoder du texte plutôt que le remodeler, voyez le [convertisseur Base64](/fr/tools/base64-converter/) ou le [générateur de hash](/fr/tools/hash-generator/).
