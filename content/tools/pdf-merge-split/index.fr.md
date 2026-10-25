---
title: "Fusionner et diviser un PDF, gratuitement"
description: "Fusionnez des PDF, divisez-les par pages ou plages, réordonnez, pivotez et supprimez des pages dans le navigateur. Vos PDF ne sont jamais envoyés. Gratuit."
intro: "**Fusionnez des PDF** en un seul fichier, **divisez un PDF** en pages ou en plages et, au passage, réordonnez, faites pivoter ou supprimez des pages, avec des miniatures à faire glisser. Tout se passe dans cet onglet du navigateur : contrats, bulletins de paie et numérisations ne quittent jamais votre appareil."
date: 2026-10-25
lastmod: 2026-10-25
reviewed: false
keywords: ["fusionner pdf", "diviser pdf", "combiner des pdf", "réorganiser pages pdf", "diviser pdf en ligne", "fusionner pdf sans envoi", "extraire des pages pdf", "pivoter pages pdf"]
tags: ["pdf", "confidentialité", "documents", "tool"]
app_category: "UtilitiesApplication"
tool_file: "/tools/pdf-merge-split/"
tool_title: "Fusionner, diviser et réorganiser des PDF"
tool_height: 760
tool_sandbox: "allow-scripts allow-same-origin allow-downloads"
howto:
  - "Déposez un ou plusieurs fichiers PDF dans le cadre, ou cliquez pour les choisir. Chaque page apparaît sous forme de miniature numérotée, dans l'ordre des fichiers."
  - "Organisez les pages : faites glisser une miniature à un nouvel emplacement, ou utilisez les boutons **←** et **→** (pratiques sur téléphone). **⟳** fait pivoter une page de 90°, **✕** l'exclut du résultat."
  - "Pour tout combiner, indiquez le **Nom du fichier** et cliquez sur **Fusionner et télécharger** : vous obtenez un seul PDF avec les pages exactement dans votre ordre."
  - "Pour diviser, choisissez **Chaque page dans son propre PDF**, ou **Par plages de pages** et saisissez des groupes comme `1-3, 4, 5-` (les numéros des miniatures ; `5-` signifie de la page 5 à la fin)."
  - "Cliquez sur **Diviser et télécharger (.zip)**. Chaque groupe devient un PDF nommé d'après le premier fichier (`rapport-part-1.pdf`…) ; avec un seul groupe, vous recevez directement le PDF."
faq:
  - q: "Mes PDF sont-ils envoyés quelque part ?"
    a: "Non. Le navigateur lit les fichiers, les affiche en aperçu avec pdf.js et les reconstruit avec pdf-lib, qui tournent tous deux dans cet onglet. La page télécharge ces bibliothèques une fois et n'envoie rien ; vous pouvez le vérifier dans l'onglet Réseau pendant la fusion."
  - q: "La fusion réduit-elle la qualité ?"
    a: "Non. Les pages sont copiées telles quelles : le texte reste du texte, les images gardent leur compression d'origine et les polices sont conservées. Rien n'est pixellisé ni recompressé, le résultat est donc aussi net que les originaux."
  - q: "Puis-je fusionner des PDF protégés par mot de passe ?"
    a: "Pas directement : un PDF chiffré ne peut pas être lu sans son mot de passe, et l'outil le signale au lieu de produire un fichier cassé. Ouvrez-le dans un lecteur PDF, enregistrez une copie sans mot de passe, puis ajoutez cette copie."
  - q: "Les liens, signets et champs de formulaire sont-ils conservés ?"
    a: "Le contenu des pages, les annotations et les liens sur les pages sont copiés. Le sommaire (signets) et la logique des formulaires interactifs appartiennent au fichier d'origine dans son ensemble et ne sont pas recréés dans le PDF fusionné : vérifiez les formulaires après la fusion."
  - q: "Quelle taille peuvent faire les fichiers ?"
    a: "Il n'y a pas de limite fixe ; tout dépend de la mémoire de l'appareil. Des documents de quelques centaines de pages fonctionnent bien sur un ordinateur. Une miniature est générée pour chaque page, les très gros fichiers mettent donc plus de temps à s'afficher."
  - q: "Que fait la rotation au fichier ?"
    a: "Elle définit la rotation de la page dans le PDF (par pas de 90°), que tous les lecteurs respectent. Le contenu n'est pas redessiné : la rotation est sans perte et s'annule en pivotant à nouveau."
  - q: "Comment extraire seulement quelques pages ?"
    a: "Utilisez **Par plages de pages** avec un seul groupe, par exemple `3-5` : vous téléchargez un PDF qui ne contient que les pages 3, 4 et 5. Vous pouvez aussi retirer avec ✕ les pages inutiles puis fusionner."
---

## Comment ça marche

### Deux bibliothèques, toutes deux locales

Lire un PDF et en écrire un sont deux tâches distinctes ; l'outil utilise donc deux bibliothèques open source, servies par ce site et chargées seulement quand vous ajoutez un fichier :

- **pdf.js** (Mozilla, Apache-2.0), le moteur du lecteur PDF de Firefox, génère une petite miniature de chaque page dans un worker en arrière-plan pour que la page reste réactive.
- **pdf-lib** (MIT) construit le résultat. Pour chaque page, dans votre ordre, il copie l'objet page du document source — flux de contenu, polices, images et annotations — dans un nouveau document avec `copyPages`, applique la rotation choisie et enregistre.

Avant tout, l'outil vérifie que chaque fichier commence par `%PDF-` : un document Word renommé ou un téléchargement corrompu est signalé avec son nom.

### Ordre des pages et plages

Les miniatures forment une seule liste pour tous les fichiers : la fusion les écrit dans cet ordre, et les numéros saisis pour la division s'y rapportent aussi. Les plages sont des groupes séparés par des virgules ; chaque groupe peut être une page seule (`4`), un intervalle (`1-3`), une fin ouverte (`5-` jusqu'à la dernière page) ou un début ouvert (`-3`). Chaque groupe devient un PDF ; plusieurs PDF sont regroupés dans un ZIP avec JSZip.

### Ce qui n'est pas repris

Le nouveau document reçoit de pdf-lib des métadonnées neuves au lieu des titres et auteurs d'origine, et les fonctions de niveau document, comme le sommaire des signets et les scripts de formulaire, ne sont pas recréées. Pour fusionner et diviser au quotidien — factures, numérisations, chapitres, diapositives — c'est exactement ce qu'il faut.

## Cas d'usage

- **Réunir des numérisations** d'un contrat ou d'un formulaire de plusieurs pages en un seul fichier avant de l'envoyer par e-mail.
- **Diviser un gros PDF** — un manuel, une documentation, une année de relevés bancaires — en chapitres ou en mois.
- **Supprimer des pages** contenant des données personnelles avant de partager un document.
- **Corriger l'ordre et l'orientation** d'un document numérisé à l'envers ou dans le désordre.
- **Constituer un dossier de candidature** : CV, lettre de motivation et attestations dans l'ordre demandé, sans les confier à un service en ligne dont vous ne savez rien.
