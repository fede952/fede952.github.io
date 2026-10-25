---
title: "Cacher du Texte dans une Image (LSB)"
description: "Cachez un message secret dans une image par stéganographie LSB, puis révélez-le. Export PNG sans perte ; tout se passe dans votre navigateur, sans envoi."
intro: "**Steganography Lab** cache un message texte dans les pixels d'une image et le relit plus tard. L'image semble identique, car chaque valeur de couleur varie au plus de 1 sur 255. Tout se passe dans votre navigateur : l'image et le message ne quittent jamais votre appareil."
date: 2026-02-05
lastmod: 2026-10-24
reviewed: false
keywords: ["stéganographie en ligne", "cacher du texte dans une image", "stéganographie lsb", "message caché dans une photo", "décoder un message caché", "stéganographie png", "message secret image", "outil stéganographie"]
tags: ["confidentialité", "sécurité", "images", "outil"]
app_category: "SecurityApplication"
tool_file: "/tools/steganography/"
tool_title: "Steganography Lab"
tool_height: 900
tool_sandbox: "allow-scripts allow-same-origin allow-downloads"
tool_allow: "clipboard-write"
howto:
  - "Dans l'onglet **Cacher un message**, déposez une image ou cliquez pour la choisir (JPG, PNG, WebP ou GIF). L'outil affiche sa taille et sa capacité en octets."
  - "Saisissez ou collez votre message. La barre de capacité se remplit pendant la saisie et passe à l'orange puis au rouge près de la limite."
  - "Cliquez sur **Encoder et Télécharger PNG**. Un fichier `stego_<timestamp>.png` est enregistré, visuellement identique à l'original."
  - "Envoyez ce PNG **en tant que fichier** (pièce jointe, lien cloud, « envoyer comme document »), pas comme une photo qu'une messagerie recompressera."
  - "Pour le lire, ouvrez l'onglet **Révéler un message**, chargez le PNG et cliquez sur **Décoder le message caché**. **Copier Texte** récupère le résultat."
faq:
  - q: "Le message caché est-il chiffré ?"
    a: "Non. La stéganographie cache l'existence du message, pas son contenu. Quiconque charge le PNG dans cet outil, ou connaît le schéma, peut le lire. Pour un contenu sensible, chiffrez d'abord le texte (par exemple avec age ou GPG) et cachez le texte chiffré."
  - q: "Pourquoi la sortie doit-elle être en PNG ?"
    a: "Le PNG est sans perte : chaque valeur de pixel est conservée exactement. Le JPEG et le WebP avec perte requantifient les couleurs à l'enregistrement et brouillent justement les bits de poids faible où se trouve le message. C'est aussi pourquoi l'onglet de révélation n'accepte que des PNG."
  - q: "Mon message a disparu après l'envoi de l'image. Pourquoi ?"
    a: "La plupart des messageries et réseaux sociaux redimensionnent et recompressent les photos, et une capture d'écran redessine les pixels. Chacune de ces opérations détruit les bits cachés. Envoyez le PNG comme fichier ou document pour qu'il arrive intact octet par octet."
  - q: "Combien de texte une image peut-elle contenir ?"
    a: "Trois bits par pixel totalement opaque, moins 19 octets d'en-tête et de terminateur. Une photo 1920×1080 contient environ 777 000 octets. Le compteur est en octets UTF-8 : les lettres accentuées en prennent deux, beaucoup d'emoji quatre."
  - q: "Les outils de stéganalyse peuvent-ils le détecter ?"
    a: "Oui. L'insertion LSB séquentielle est le cas d'école que les tests statistiques comme le khi-deux ou l'analyse RS savent repérer, surtout quand une grande part de la capacité est utilisée. Voyez-le comme un outil pédagogique et de confidentialité légère, pas de communication clandestine face à un adversaire compétent."
  - q: "Est-ce que ça marche avec des PNG transparents ?"
    a: "Oui. Seuls les pixels totalement opaques portent des données, car le navigateur stocke les pixels semi-transparents sous forme prémultipliée et leurs bits faibles ne survivraient pas. Les zones transparentes restent intactes et réduisent simplement la capacité."
  - q: "Mon image est-elle envoyée quelque part ?"
    a: "Non. Le fichier est lu avec l'API FileReader et traité sur un canvas dans l'onglet du navigateur. Il n'y a aucun serveur : vous pouvez charger la page, passer hors ligne, et l'outil fonctionne toujours."
---

## Comment ça marche

La technique est la **substitution du bit de poids faible (LSB)**, la forme classique de stéganographie d'image (explication détaillée dans le [guide Stéganographie 101](/fr/learn/guides/steganography-101-hidden-messages/)).

**1. Construire la charge utile.** Votre texte est encodé en UTF-8 et encadré ainsi :

```
STEGO_V1::<votre message>\0\0\0END\0\0\0
```

Le préfixe `STEGO_V1::` permet au décodeur de savoir immédiatement si une image contient un message ; le marqueur `END` entouré d'octets nuls indique où il s'arrête.

**2. Lire les pixels.** L'image est dessinée sur un canvas HTML à sa taille réelle, lissage désactivé, et `getImageData()` renvoie chaque pixel sous forme d'octets rouge, vert, bleu et alpha.

**3. Un bit par canal de couleur.** Les bits de la charge, du poids fort au poids faible, sont écrits un par un dans le bit le plus bas des octets R, V et B de chaque pixel totalement opaque, dans l'ordre de lecture depuis le coin supérieur gauche. Chaque octet devient `(valeur & 0xFE) | bit` : un canal varie de 0 ou 1 et la différence est invisible. L'alpha n'est jamais modifié et les pixels non totalement opaques sont ignorés, car le canvas prémultiplie leurs couleurs et les bits faibles seraient perdus.

**4. Exporter sans perte.** Le canvas modifié est enregistré avec `toBlob('image/png')`. Effet secondaire : la sortie ne contient **aucune métadonnée EXIF** (appareil, GPS, date), puisque le canvas ne connaît que des pixels.

**5. Décoder.** L'onglet Révéler fait l'inverse : il collecte les bits faibles des mêmes canaux, reconstruit les octets et compare les dix premiers à `STEGO_V1::`. S'ils ne correspondent pas, il s'arrête aussitôt, donc une grande photo vierge est rejetée presque instantanément ; sinon il lit jusqu'au marqueur de fin et retransforme les octets en texte.

| Image | Pixels opaques | Capacité |
|---|---|---|
| 800×600 | 480 000 | ≈ 179 981 octets |
| 1920×1080 | 2 073 600 | ≈ 777 581 octets |
| 4000×3000 | 12 000 000 | ≈ 4,5 Mo |

Plus vous remplissez la capacité, plus l'image est facile à repérer par stéganalyse statistique. Un message court dans une grande photo bruitée est bien plus difficile à détecter qu'un long message dans un graphique aux aplats de couleur.

## Cas d'usage

- **Apprendre et enseigner.** Voyez exactement ce que fait l'insertion LSB, puis essayez de la casser : recompressez le PNG en JPEG et regardez le message disparaître.
- **Entraînement CTF.** Les épreuves de stéganographie cachent souvent des flags dans les LSB ; encoder vos propres échantillons rend le motif facile à reconnaître avec des outils comme `zsteg` ou StegSolve.
- **Marquer vos propres images.** Insérez une mention (auteur, date) dans un PNG que vous partagez en fichier. Elle ne survit pas à l'édition, mais prouve qu'une copie est intacte.
- **Un secret pour s'amuser.** Cachez un message dans une photo de vacances pour un ami qui saura où chercher.
- **Transporter un texte déjà chiffré.** Collez un texte chiffré (par exemple une sortie GPG en ASCII armor) pour combiner confidentialité et discrétion.

Pour la tâche inverse, supprimer les données cachées dans les métadonnées d'une photo plutôt que dans ses pixels, utilisez l'[EXIF Cleaner](/fr/tools/exif-cleaner/).
