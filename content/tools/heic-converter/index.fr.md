---
title: "Convertir HEIC en JPG, sans envoi"
description: "Convertissez les photos HEIC de l'iPhone en JPG ou PNG dans le navigateur : par lots, qualité réglable, suppression EXIF/GPS au choix, ZIP. Sans envoi."
intro: "Transformez vos **photos HEIC d'iPhone en JPG ou PNG** sans les envoyer nulle part : déposez un ou cent fichiers, choisissez le format et la qualité, décidez de supprimer ou non les métadonnées EXIF et la position GPS, puis téléchargez chaque fichier ou un seul ZIP. Le décodeur tourne dans cet onglet du navigateur."
date: 2026-10-25
lastmod: 2026-10-25
reviewed: false
keywords: ["convertir heic en jpg", "heic en jpg", "convertisseur heic", "heic en png", "photo iphone en jpg", "ouvrir fichier heic", "convertir heic en ligne", "heic jpg gratuit"]
tags: ["images", "confidentialité", "convertisseur", "tool"]
app_category: "MultimediaApplication"
tool_file: "/tools/heic-converter/"
tool_title: "Convertisseur HEIC vers JPG et PNG"
tool_height: 720
tool_sandbox: "allow-scripts allow-same-origin allow-downloads"
howto:
  - "Déposez vos photos `.heic` ou `.heif` dans le cadre, ou cliquez pour les choisir. Vous pouvez en ajouter plusieurs à la fois, et d'autres ensuite."
  - "La première fois, la page charge son décodeur HEIC (environ 1,5 Mo, une fois par visite). Chaque photo est ensuite décodée et convertie à son tour ; une miniature et la nouvelle taille s'affichent à côté du nom."
  - "Choisissez **JPG** (fichiers plus légers, **Qualité JPG** réglable) ou **PNG** (sans perte, plus lourd). Changer une option reconvertit les photos déjà dans la liste."
  - "Laissez **Supprimer les métadonnées (EXIF, position GPS)** coché pour obtenir des fichiers propres, ou décochez-le pour garder dans le JPG les données de l'appareil et la position."
  - "Cliquez sur **Télécharger** pour une photo, ou sur **Tout télécharger (.zip)** pour enregistrer tous les fichiers convertis dans une seule archive."
faq:
  - q: "Mes photos sont-elles envoyées sur un serveur ?"
    a: "Non. Les fichiers sont lus avec l'API File du navigateur et décodés par une version WebAssembly de libheif qui s'exécute dans cet onglet. Les seules requêtes réseau servent à charger le décodeur ; vos photos ne quittent jamais l'appareil. Vous pouvez le vérifier dans l'onglet Réseau du navigateur pendant la conversion."
  - q: "Pourquoi l'iPhone enregistre-t-il les photos en HEIC ?"
    a: "Le HEIC contient une image compressée en HEVC (H.265) dans un conteneur HEIF. À qualité comparable, les fichiers pèsent environ deux fois moins qu'un JPEG, d'où son usage par défaut sur iOS. Beaucoup de logiciels Windows, de sites et d'appareils anciens ne savent toujours pas l'ouvrir, d'où le besoin de convertir."
  - q: "Vais-je perdre en qualité ?"
    a: "La conversion en JPEG recompresse l'image. À la qualité par défaut de 85, la différence est très difficile à voir et le fichier reste léger ; choisissez 95–100 si vous comptez retoucher la photo. Le PNG est sans perte mais pèse souvent trois à cinq fois plus que le HEIC d'origine."
  - q: "Que supprime « Supprimer les métadonnées » ?"
    a: "Tout sauf les pixels : les données EXIF de l'appareil, la date et l'heure et surtout la position GPS, qui peut révéler où vous habitez ou travaillez. Option décochée, le convertisseur copie le bloc EXIF d'origine dans le JPEG et réinitialise la balise d'orientation, car le décodeur a déjà fait pivoter l'image."
  - q: "Mon HEIC contient plusieurs images (Live Photo, rafale). Laquelle est convertie ?"
    a: "L'image principale, celle qu'affiche l'app Photos. La partie animée d'une Live Photo est un fichier vidéo séparé et n'est pas incluse."
  - q: "Y a-t-il une limite de taille ou de nombre ?"
    a: "Seulement la mémoire de votre appareil. Chaque photo est décodée en pixels bruts (une photo de 12 mégapixels occupe environ 48 Mo pendant la conversion) ; les très gros lots vont donc plus vite sur un ordinateur que sur un ancien téléphone."
  - q: "Puis-je convertir un HEIC en PNG avec transparence ?"
    a: "Les photos des appareils de téléphone n'ont pas de transparence. Si une image HEIF possède un canal alpha, le PNG le conserve ; le JPEG ne gère pas la transparence et la remplit en noir."
---

## Comment ça marche

### Décoder sans serveur

Les navigateurs autres que Safari ne savent pas ouvrir le HEIC seuls, car ce format enveloppe des images compressées en **HEVC** dans un conteneur **HEIF** (ISO/IEC 23008-12). Cette page embarque **libheif** — la bibliothèque open source de référence pour le HEIF, compilée en WebAssembly par le projet libheif-js — et ne la charge que lorsque vous déposez le premier fichier, pour que la page reste légère.

Pour chaque fichier, le convertisseur :

1. Lit les octets avec l'API File et vérifie dans la boîte `ftyp` que la marque est bien HEIF (`heic`, `heix`, `mif1`…) : un JPEG renommé est signalé au lieu de bloquer le décodeur.
2. Décode l'image principale avec libheif en un bitmap RGBA. La rotation et le miroir enregistrés dans le fichier (`irot`, `imir`) sont appliqués à cette étape.
3. Dessine le bitmap sur un `<canvas>` et l'encode avec `canvas.toBlob()` en JPEG à la qualité choisie, ou en PNG.

### Métadonnées

Un canvas ne porte jamais de métadonnées : un fichier converti est donc propre par défaut. Si vous choisissez de les garder, le convertisseur analyse lui-même le conteneur HEIF — la boîte `meta`, la liste des éléments (`iinf`) et leurs emplacements (`iloc`) — pour trouver l'élément de type `Exif` et l'insère dans le JPEG sous forme de segment **APP1** standard. Dans la copie, la balise `Orientation` est mise à 1 (normale), sinon les visionneuses feraient pivoter une photo déjà droite. La sortie PNG est toujours sans métadonnées.

### Téléchargement en ZIP

Avec plusieurs fichiers, **Tout télécharger** charge une petite bibliothèque ZIP (JSZip), y ajoute chaque fichier converti et enregistre une seule archive. Les noms en double reçoivent un suffixe numérique (`IMG_0001-2.jpg`).

## Cas d'usage

- **Envoyer des photos d'iPhone à des utilisateurs de Windows ou à des formulaires** qui n'acceptent que le JPG ou le PNG : candidatures, sinistres d'assurance, démarches administratives.
- **Publier sur le web sans révéler votre position.** Convertissez et supprimez l'EXIF en une seule étape avant de publier sur une place de marché ou un forum.
- **Archiver.** Convertissez en JPG un dossier de photos de vacances pour le vieil ordinateur d'un proche ou un cadre photo numérique.
- **Designers et développeurs** qui reçoivent des captures ou des maquettes en HEIC et ont besoin de PNG pour la documentation.
- **Images sensibles** — documents, pièces d'identité, photos médicales — qui ne devraient pas passer par un convertisseur en ligne impossible à vérifier.
