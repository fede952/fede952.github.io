---
title: "Compresser une Image : JPG, PNG, WebP"
description: "Réduisez le poids de vos images JPG, PNG et WebP dans le navigateur : qualité, poids cible, largeur maximale, conversion WebP. Sans envoi ni inscription."
intro: "**PixelShrink** compresse et convertit les images sur votre propre appareil. Déposez une photo, choisissez la qualité, un poids cible ou une largeur maximale, et téléchargez un JPG, PNG ou WebP plus léger. L'image n'est jamais envoyée."
date: 2026-02-03
lastmod: 2026-10-24
reviewed: false
keywords: ["compresser image", "réduire poids image", "compresseur d'images en ligne", "compresser jpg", "compresser png", "convertir en webp", "redimensionner image", "compresser photo sans upload"]
tags: ["images", "compression", "vie privée", "outil"]
app_category: "MultimediaApplication"
tool_file: "/tools/pixel-shrink/"
tool_title: "PixelShrink, compresseur d'images"
tool_height: 900
tool_sandbox: "allow-scripts allow-same-origin allow-downloads"
howto:
  - "Glissez une image dans la zone de dépôt ou cliquez pour choisir un fichier. PNG, JPEG, WebP et AVIF sont acceptés ; l'aperçu affiche le poids et les dimensions."
  - "Choisissez le **format de sortie** : garder l'original ou convertir en JPEG, PNG ou WebP. Pour les photos, le WebP est généralement le plus léger."
  - "Réglez la **qualité** (1–100, 75 par défaut), un **poids maximal** en Mo et une **largeur maximale** en pixels : le plus grand côté est réduit à cette valeur en gardant les proportions."
  - "Cliquez sur **Compresser l’Image**. Le panneau avant/après affiche les deux poids, les deux dimensions et le pourcentage gagné."
  - "Cliquez sur **Télécharger l’Image Compressée** pour enregistrer le résultat. S'il n'est pas plus léger que l'original, l'outil vous le signale : gardez l'original ou essayez un autre format."
faq:
  - q: "Mes images sont-elles envoyées sur un serveur ?"
    a: "Non. L'image est décodée, redimensionnée et réencodée dans votre navigateur, dans un Web Worker en arrière-plan. Rien n'est envoyé : une fois la page chargée, vous pouvez passer hors ligne, l'outil fonctionne toujours. Il convient donc aussi aux captures de documents, de pièces d'identité ou de tout ce qui est privé."
  - q: "Quelle qualité choisir ?"
    a: "Pour les photos, 70–80 est le bon compromis : le fichier maigrit beaucoup et les différences sont difficiles à voir à taille normale. Descendez à 50–60 pour les vignettes et aperçus. Au-delà de 90, le fichier grossit vite sans gain visible."
  - q: "Faut-il convertir en WebP ?"
    a: "Pour le web, généralement oui. Les fichiers WebP sont en moyenne 25 à 35 % plus légers qu'un JPEG de qualité comparable, et tous les navigateurs actuels les affichent. Restez en JPEG si l'image part vers un système qui n'accepte que le JPG, comme certains formulaires ou services d'impression."
  - q: "Pourquoi mon PNG est-il devenu plus lourd ?"
    a: "Le PNG est sans perte : une photographie enregistrée en PNG pèse souvent plus que le JPEG d'origine. PixelShrink allège les PNG en limitant la palette de couleurs, ce qui marche très bien pour les captures, logos et graphismes en aplats, et mal pour les photos. Pour les photos, choisissez WebP ou JPEG."
  - q: "Puis-je compresser une image sous un poids précis, par exemple 200 Ko ?"
    a: "Réglez le **poids maximal** sur 0,2 Mo. Si le premier encodage est trop lourd, la bibliothèque le recommence jusqu'à 10 fois en baissant un peu la qualité et les dimensions à chaque passage, et s'arrête dès que le fichier tient dans la limite. Pour des images très grandes ou détaillées, baissez aussi la largeur maximale."
  - q: "La compression supprime-t-elle les données EXIF et la position GPS ?"
    a: "Oui. L'image est redessinée sur un canvas puis réencodée sans recopier les métadonnées : les champs EXIF comme le modèle d'appareil, la date et les coordonnées GPS disparaissent. Pour retirer seulement les métadonnées sans recompresser, utilisez EXIF Cleaner."
  - q: "Pourquoi n'y a-t-il pas de sortie AVIF ?"
    a: "La sortie est produite par l'encodeur d'images du navigateur lui-même, et la plupart des navigateurs savent afficher l'AVIF mais pas le créer à partir d'un canvas. PixelShrink le vérifie au chargement et ne propose l'AVIF que si votre navigateur sait vraiment l'encoder, au lieu de produire en douce un PNG nommé .avif."
---

## Comment ça marche

PixelShrink est une interface légère au-dessus de [browser-image-compression](https://github.com/Donaldcwl/browser-image-compression) (v2.0.2, hébergée sur ce site). Quand vous cliquez sur Compresser, le travail passe dans un **Web Worker** : la page reste réactive même avec une photo de 20 mégapixels.

1. **Décodage.** Le fichier est décodé en bitmap avec `createImageBitmap` (ou un élément `<img>` en solution de repli), et l'orientation EXIF est appliquée pour que les photos en portrait ne soient pas pivotées.
2. **Redimensionnement.** Si le plus grand côté dépasse la *largeur maximale*, l'image est dessinée sur un canvas plus petit aux mêmes proportions. Une photo de 6000 × 4000 avec une limite de 2048 px devient 2048 × 1365.
3. **Encodage.** Le JPEG et le WebP sont encodés par le navigateur (`canvas.toBlob` / `OffscreenCanvas.convertToBlob`) avec votre réglage de qualité. Le PNG passe par **UPNG.js**, qui quantifie l'image sur une palette d'au plus 4096 × qualité couleurs (3 072 couleurs au réglage par défaut de 75) avant d'écrire un PNG sans perte : c'est l'astuce qui divise par deux ou plus le poids des captures et des graphismes d'interface.
4. **Respect du poids cible.** Si le résultat dépasse encore le *poids maximal*, l'encodage est répété jusqu'à **10 fois**. À chaque passage, la qualité est multipliée par 0,95 (0,85 pour le PNG) et les dimensions peuvent être réduites d'un facteur 0,95, jusqu'à ce que le fichier tienne ou que les passages soient épuisés.

Le panneau avant/après compare le fichier d'origine au résultat, et le téléchargement est une URL locale `blob:` nommée `votrefichier-compressed.<format>`. L'image étant réencodée à partir des pixels, **les métadonnées comme l'EXIF et le GPS ne sont pas conservées**.

### Quel format choisir ?

| Contenu | Meilleur format | Pourquoi |
|---|---|---|
| Photos pour un site ou un blog | WebP, qualité 70–80 | Fichiers les plus légers, lus par tous les navigateurs |
| Photos pour e-mail, formulaires, impression | JPEG, qualité 75–85 | Accepté partout |
| Captures, schémas, logos | PNG ou WebP | Les contours nets et les aplats se compressent bien |
| Images avec transparence | PNG ou WebP | Le JPEG n'a pas de canal alpha |

L'**AVIF** n'apparaît que si le navigateur sait réellement l'*encoder* depuis un canvas. La plupart n'en sont pas encore capables, et PixelShrink le vérifie au chargement plutôt que de deviner.

## Cas d'usage

- **Des pages web plus rapides.** Les grandes images d'en-tête sont la cause la plus fréquente d'un mauvais Largest Contentful Paint. Un JPEG de 3 Mo converti en WebP de 2000 px à la qualité 75 passe souvent sous les 300 Ko.
- **Limites d'envoi.** Démarches administratives, sites d'emploi et tickets de support limitent souvent les pièces jointes à 1 ou 2 Mo. Fixez le poids maximal et laissez l'outil trouver la bonne qualité.
- **E-mail et messagerie.** Envoyez cinq photos de vacances au lieu d'une quand chacune pèse dix fois moins.
- **Documents privés.** Allégez le scan d'une pièce d'identité ou d'un contrat sans le confier à un service en ligne inconnu.
- **Ressources d'applis et de jeux.** Convertissez des sprites PNG ou des captures en fichiers plus légers avant de les ajouter à un dépôt.
