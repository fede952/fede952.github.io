---
title: "Formateur et validateur JSON, JSON en YAML"
description: "Formatez, minifiez et validez du JSON avec ligne et colonne exactes de l'erreur, triez les clés, parcourez l'arbre, convertissez en YAML ou CSV. Privé."
intro: "Collez du JSON pour le **formater** avec 2 ou 4 espaces ou des tabulations, le **minifier**, le **valider** avec la *ligne et la colonne* exactes de la première erreur, **trier les clés**, le parcourir sous forme d'**arbre** repliable ou convertir **JSON en YAML**, **YAML en JSON** et **JSON en CSV**. Les fichiers de plusieurs mégaoctets sont traités par un worker en arrière-plan ; rien n'est envoyé."
date: 2026-10-25
lastmod: 2026-10-25
reviewed: false
keywords: ["formateur json", "validateur json", "formater json en ligne", "json beautifier", "json en yaml", "yaml en json", "json en csv", "minifier json"]
tags: ["outils-développeurs", "json", "yaml", "tool"]
app_category: "DeveloperApplication"
tool_file: "/tools/json-formatter/"
tool_title: "Formateur, validateur et convertisseur JSON"
tool_height: 820
tool_sandbox: "allow-scripts allow-same-origin allow-downloads"
tool_allow: "clipboard-write"
howto:
  - "Collez votre JSON dans **Entrée**, ouvrez un fichier `.json` avec **Ouvrir un fichier** ou cliquez sur **Exemple** pour essayer."
  - "Cliquez sur **Formater** (ou Ctrl/⌘ + Entrée) pour l'indenter selon l'**Indentation** choisie ; **Minifier** supprime tous les espaces. Cochez **Trier les clés** pour classer par ordre alphabétique les clés de chaque objet."
  - "Si le JSON est invalide, la ligne d'état indique le problème et sa position — par exemple *Ligne 3, colonne 14 : virgule finale* — et affiche la ligne fautive avec un repère sous le caractère exact."
  - "Convertissez avec **En YAML** ou **En CSV** (choisissez le **Séparateur CSV**). Pour l'inverse, passez à **Entrée YAML**, collez du YAML et cliquez sur **Formater** pour obtenir du JSON."
  - "Basculez la sortie entre **Texte** et **Arbre** pour parcourir les grandes structures, puis **Copier** ou **Télécharger** le résultat."
faq:
  - q: "Mon JSON est-il envoyé à un serveur ?"
    a: "Non. L'analyse, le formatage et la conversion se font dans votre navigateur — au-delà de 2 Mo, dans un Web Worker du même onglet. La page n'envoie aucune requête avec vos données : réponses d'API, jetons et fichiers de configuration restent sur votre machine."
  - q: "Pourquoi « virgule finale » ?"
    a: "Le JSON n'accepte pas de virgule après le dernier élément d'un objet ou d'un tableau, même si JavaScript l'autorise. `[1, 2,]` et `{\"a\": 1,}` ne sont pas du JSON valide : supprimez la dernière virgule. Autres erreurs fréquentes reconnues : apostrophes au lieu de guillemets, clés sans guillemets, commentaires et valeurs NaN ou Infinity."
  - q: "Comment trouve-t-il la ligne et la colonne d'une erreur ?"
    a: "Les messages de JSON.parse varient d'un navigateur à l'autre et certains ne donnent qu'une position en caractères. En cas d'échec, l'outil relit le texte avec son propre analyseur strict conforme à la RFC 8259, qui s'arrête au premier caractère impossible dans un JSON valide et indique sa ligne et sa colonne."
  - q: "Comment le JSON est-il converti en CSV ?"
    a: "Un tableau d'objets donne une ligne par objet. Les objets imbriqués deviennent des colonnes pointées (`address.city`), les tableaux dans une ligne sont écrits en texte JSON, et les colonnes sont l'union de toutes les clés dans leur ordre d'apparition. Les valeurs avec virgules, guillemets ou retours à la ligne sont mises entre guillemets comme l'exige la RFC 4180. Un tableau de tableaux est écrit ligne par ligne."
  - q: "Les commentaires et ancres YAML sont-ils conservés ?"
    a: "Du YAML vers le JSON, ancres et alias sont résolus en valeurs simples et les commentaires disparaissent, le JSON ne connaissant ni l'un ni l'autre. Du JSON vers le YAML, on obtient du YAML en blocs sans ancres : les structures répétées sont écrites en entier."
  - q: "Trier les clés modifie-t-il mes données ?"
    a: "Aucune valeur ne change. Les clés des objets sont réordonnées par point de code Unicode (majuscules avant minuscules) à tous les niveaux ; les tableaux gardent leur ordre, qui fait partie des données. Une sortie triée est pratique pour les diffs et pour des fichiers stables sous gestion de versions."
  - q: "Quelle taille de fichier est acceptée ?"
    a: "Des dizaines de mégaoctets sur un ordinateur. Au-delà de 2 Mo, le formatage et la minification tournent dans un worker en arrière-plan pour que la page reste réactive. La vue en arbre ne crée les nœuds qu'à l'ouverture et affiche au plus 500 enfants par nœud à la fois."
---

## Comment ça marche

### Une validation qui s'explique

L'entrée est analysée avec le `JSON.parse` natif du navigateur, l'analyseur le plus rapide et le plus conforme disponible. En cas d'échec, un second analyseur, volontairement petit, parcourt le texte selon la grammaire de la RFC 8259 — objets, tableaux, chaînes et leurs règles d'échappement, nombres sans zéro de tête, `true`, `false`, `null` — et s'arrête au premier caractère qui ne peut pas prolonger un document valide. Cette position est convertie en ligne et colonne et associée à une explication claire : virgule finale, deux-points manquant, chaîne entre apostrophes, tabulation non échappée dans une chaîne, ou texte après la fin du document.

### Formater, minifier et trier

Le formatage utilise `JSON.stringify` avec l'indentation choisie (2 espaces, 4 espaces ou une tabulation). La minification écrit la même structure sans espaces. **Trier les clés** reconstruit chaque objet avec ses clés dans l'ordre des points de code avant la sérialisation ; l'ordre des tableaux ne change jamais. Les nombres sont écrits tels que JavaScript les lit : les entiers au-delà de 2^53 perdent en précision, gardez ces identifiants sous forme de chaînes.

### Grandes entrées

Au-delà de 2 Mo en UTF-8, le formatage et la minification sont confiés à un **Web Worker**, un fil d'exécution en arrière-plan du même onglet, pour que la saisie et le défilement restent fluides pendant le traitement d'un gros export d'API. La vue en arbre est construite à la demande : les enfants d'un nœud ne sont créés qu'à son ouverture.

### Conversions

La prise en charge du YAML repose sur **js-yaml** (MIT), servie par ce site et chargée seulement à la première utilisation du YAML. Le YAML est lu avec le schéma sûr par défaut : il ne peut pas créer d'objets personnalisés ni exécuter de code. Le CSV est produit par l'outil lui-même, avec les guillemets et fins de ligne de la RFC 4180.

## Cas d'usage

- **Déboguer des API.** Indentez une réponse tenant sur une ligne, trouvez dans l'arbre le champ voulu ou repérez exactement où un payload modifié à la main se casse.
- **Configuration.** Convertissez un extrait Kubernetes ou Docker Compose entre YAML et JSON, ou validez un `package.json` ou `tsconfig.json` après modification.
- **Exports de données.** Transformez un tableau d'enregistrements en CSV pour un tableur, avec les champs imbriqués aplatis en colonnes.
- **Revue de code et gestion de versions.** Triez les clés et formatez de façon cohérente pour que les diffs montrent de vrais changements et non des réordonnancements.
- **Données sensibles.** Inspectez des payloads JWT, des corps de webhooks ou des journaux contenant des données personnelles sans les coller sur un site tiers.
