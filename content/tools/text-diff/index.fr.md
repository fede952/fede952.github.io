---
title: "Comparer deux textes en ligne (diff)"
description: "Comparez deux textes ou fichiers côte à côte ou en ligne, surlignez mots ou caractères, ignorez espaces ou casse et copiez un diff unifié. Privé, local."
intro: "Collez deux versions d'un texte, d'un fichier de configuration ou d'un morceau de code pour voir chaque ligne **ajoutée**, **supprimée** et **modifiée**, **côte à côte** ou **en ligne**, avec les **mots** ou les **caractères** modifiés surlignés. Ignorez les espaces ou la casse, repliez les lignes inchangées et **copiez un diff unifié** applicable avec `git apply` ou `patch`. Rien ne quitte votre navigateur."
date: 2026-10-25
lastmod: 2026-10-25
reviewed: false
keywords: ["comparer deux textes", "comparateur de texte", "diff en ligne", "trouver les différences texte", "comparer des fichiers", "diff unifié", "text compare", "comparaison de texte"]
tags: ["outils-développeurs", "diff", "texte", "tool"]
app_category: "DeveloperApplication"
tool_file: "/tools/text-diff/"
tool_title: "Comparateur de texte (diff)"
tool_height: 900
tool_sandbox: "allow-scripts allow-same-origin allow-downloads"
tool_allow: "clipboard-write"
howto:
  - "Collez l'ancienne version dans **Original** et la nouvelle dans **Modifié**, ou chargez chacune avec **Ouvrir un fichier**. Cliquez sur **Exemple** pour essayer avec deux versions d'une configuration nginx."
  - "Le résultat se met à jour pendant la saisie. Choisissez **Côte à côte** pour voir les deux versions en colonnes ou **En ligne** pour une seule colonne avec des lignes − et + (par défaut sur mobile)."
  - "Réglez **Surligner** sur **Mots** ou **Caractères** pour choisir la précision du marquage dans une ligne modifiée."
  - "Cochez **Ignorer les espaces** pour considérer identiques l'indentation et les espaces multiples, et **Ignorer la casse** pour ne pas distinguer majuscules et minuscules."
  - "Les longues portions inchangées sont repliées à trois lignes de contexte ; cliquez sur une barre *⋯ lignes inchangées* pour la déplier. Utilisez **Copier le diff unifié** ou **Télécharger le .diff** pour partager la modification sous forme de patch."
faq:
  - q: "Mes textes sont-ils envoyés quelque part ?"
    a: "Non. La comparaison se fait entièrement dans votre navigateur avec la bibliothèque open source jsdiff, servie par ce site. Rien de ce que vous collez ou ouvrez n'est envoyé à un serveur : vous pouvez comparer des contrats, des fichiers de configuration contenant des secrets ou du code privé."
  - q: "Quelle différence entre surligner les mots et les caractères ?"
    a: "Dans les deux cas, les textes sont d'abord appariés ligne par ligne. Dans chaque ligne modifiée, le mode mots marque les mots entiers et les signes de ponctuation qui diffèrent — le plus lisible pour la prose et la plupart du code. Le mode caractères marque chaque caractère et révèle une faute d'une lettre ou un chiffre changé dans un identifiant ou un nombre long."
  - q: "Que fait exactement « Ignorer les espaces » ?"
    a: "Il ignore les espaces en début et en fin de ligne et la quantité d'espaces entre les mots : `a  =  1` et `a = 1` comptent comme la même ligne, et les blocs réindentés n'apparaissent pas comme modifiés. Un espace entre deux mots auparavant collés reste une différence. Les lignes vides sont toujours comparées comme des lignes."
  - q: "Qu'est-ce qu'un diff unifié et comment l'appliquer ?"
    a: "C'est le format texte standard d'une modification, utilisé par git, les outils de revue de code et patch : des en-têtes `---` et `+++`, puis des blocs commençant par `@@` avec les lignes supprimées précédées de − et les lignes ajoutées de +, plus trois lignes de contexte. Enregistrez-le dans un fichier `.diff` et lancez `git apply modif.diff` ou `patch -p0 < modif.diff`."
  - q: "Comment l'outil décide-t-il qu'une ligne a été modifiée plutôt que supprimée puis ajoutée ?"
    a: "Il applique l'algorithme de diff de Myers aux lignes entières pour trouver le plus petit ensemble de suppressions et d'ajouts. Quand un bloc de lignes supprimées est directement suivi de lignes ajoutées, elles sont appariées une à une comme lignes modifiées. Si une paire partage moins d'environ 30 % de son contenu, elle est affichée comme remplacée, sans surlignage interne."
  - q: "Peut-il comparer de gros fichiers ?"
    a: "Oui, jusqu'à plusieurs mégaoctets. Au-delà d'environ 400 000 caractères, la comparaison se fait quand vous cliquez sur Comparer plutôt qu'à chaque frappe. L'affichage montre jusqu'à 4 000 lignes ; le diff unifié contient toujours le résultat complet. Des textes trop différents pour être comparés à temps sont signalés au lieu de figer la page."
  - q: "Gère-t-il les fins de ligne Windows ?"
    a: "Oui. Les fins de ligne CRLF et CR sont normalisées avant la comparaison : le même fichier enregistré sous Windows et sous Linux est considéré comme identique. L'absence de retour à la ligne final est ignorée à l'affichage et signalée dans le diff unifié."
---

## Comment ça marche

### D'abord les lignes, puis les mots ou les caractères

Les deux textes sont découpés en lignes et comparés avec l'**algorithme de diff de Myers** (celui de `git diff`), qui trouve la plus courte suite de suppressions et d'ajouts transformant l'original en texte modifié. Les lignes supprimées directement suivies de lignes ajoutées sont appariées comme *modifiées*, et chaque paire est à nouveau comparée, jeton par jeton : mots, espaces et signes de ponctuation isolés, ou caractères individuels. Seuls les jetons différents sont surlignés.

### Des options qui ne réécrivent pas votre texte

**Ignorer les espaces** et **Ignorer la casse** changent la façon dont les lignes et les jetons sont *comparés*, pas ce qui est affiché : chaque colonne montre exactement ce que vous avez collé. L'affichage reste ainsi fidèle quand, par exemple, un bloc de code a été réindenté : les lignes correspondent et la colonne de droite montre quand même la nouvelle indentation.

### Diff unifié

Les boutons **Copier le diff unifié** et **Télécharger le .diff** produisent un patch standard avec trois lignes de contexte, avec les noms des fichiers en en-tête si vous les avez ouverts (sinon `original.txt` et `changed.txt`). Appliqué à l'original, il redonne exactement le texte modifié ; les tests de cet outil le vérifient avec `git apply`.

## Cas d'usage

- **Code et configuration.** Voyez ce qui a changé entre deux versions d'un fichier nginx, Docker Compose ou YAML avant de le déployer, sans rien committer.
- **Documents et contrats.** Repérez chaque mot modifié entre deux versions d'un contrat, d'une politique ou d'un article.
- **Journaux et exports.** Comparez deux sorties de commande, exports CSV ou listes pour repérer les lignes apparues ou disparues.
- **Partager une modification.** Transformez votre modification en fichier `.diff` qu'un collègue peut appliquer avec git ou coller dans un ticket.
- **Vérifier un copier-coller.** Assurez-vous qu'un script, une clé ou un extrait copié d'un système à l'autre est arrivé sans modification invisible — passez en mode caractères pour le plus grand détail.
