---
title: "Effet Glitch pour Photos en Ligne"
description: "Ajoutez des effets glitch à vos photos : RGB shift, pixel sorting, scanlines et bruit, presets VHS et cyberpunk. PNG pleine résolution, sans envoi."
intro: "**GlitchForge** transforme une photo en glitch art : séparation chromatique RVB, pixel sorting, scanlines façon CRT et bruit numérique, dosés avec quatre curseurs ou des préréglages en un clic. L'image est traitée sur un canvas dans votre navigateur et exportée en PNG pleine résolution."
date: 2026-02-03
lastmod: 2026-10-24
reviewed: false
keywords: ["effet glitch", "glitch art en ligne", "effet rgb split", "pixel sorting en ligne", "effet vhs photo", "effet cyberpunk photo", "effet aberration chromatique", "photo glitch"]
tags: ["images", "design", "créatif", "outil"]
app_category: "MultimediaApplication"
tool_file: "/tools/glitch-forge/"
tool_title: "GlitchForge, générateur de glitch art"
tool_height: 900
tool_sandbox: "allow-scripts allow-same-origin allow-downloads"
howto:
  - "Déposez un JPEG, PNG ou WebP sur la zone du canvas, ou cliquez pour choisir un fichier."
  - "Essayez d'abord un préréglage : **VHS**, **Cyberpunk**, **Corrupt** ou **Subtle**."
  - "Affinez avec les curseurs : **Amount** (contraste, bruit et déchirures), **RGB Shift**, **Scanlines** et **Pixel Sort**. L'aperçu se met à jour pendant que vous les faites glisser."
  - "Cliquez sur **Download Cyberpunk Image** pour enregistrer `glitchforge-export.png` à la résolution d'origine."
  - "Cliquez sur **Reset Image** pour remettre tous les curseurs à zéro et recommencer."
faq:
  - q: "Ma photo est-elle envoyée quelque part ?"
    a: "Non. L'image est dessinée sur un canvas HTML et chaque effet est calculé sur ses pixels en JavaScript, dans votre navigateur. Rien n'est envoyé à un serveur : vous pouvez l'utiliser sans crainte avec des photos personnelles."
  - q: "Quelle est la résolution du téléchargement ?"
    a: "La résolution d'origine. L'aperçu est réduit pour tenir à l'écran, mais l'export redessine l'image en pleine largeur et hauteur, applique les mêmes réglages et enregistre un PNG sans perte."
  - q: "Pourquoi le téléchargement diffère-t-il un peu de l'aperçu ?"
    a: "Le bruit et les déchirures horizontales sont aléatoires et sont générés à nouveau pour l'export, à une autre taille. Le caractère de l'effet reste le même, mais les pixels de bruit et la position des bandes changent, comme à chaque mouvement de curseur."
  - q: "Qu'est-ce que le pixel sorting ?"
    a: "Un effet popularisé par des artistes glitch comme Kim Asendorf : les pixels d'une zone sont triés par luminosité et les zones claires s'étirent en traînées. GlitchForge trie verticalement les suites de pixels lumineux : les hautes lumières coulent vers le bas tandis que les zones sombres restent intactes."
  - q: "Qu'est-ce que l'effet RGB shift ?"
    a: "Il imite l'aberration chromatique ou un signal analogique décalé : le canal rouge est déplacé vers la droite et le bleu vers la gauche, ce qui laisse des franges colorées sur chaque contour. À pleine intensité, le décalage vaut 4 % de la largeur de l'image."
  - q: "Puis-je utiliser les images commercialement ?"
    a: "Le résultat est votre propre photo transformée par un algorithme : les droits sont ceux de l'image d'origine. L'outil n'ajoute aucun filigrane et ne revendique rien sur le résultat."
---

## Comment ça marche

Au chargement, l'image est dessinée sur un canvas mis à l'échelle de l'aperçu, et une copie propre de ses pixels (`getImageData`) est conservée. À chaque mouvement de curseur, les effets sont appliqués à une nouvelle copie de ces pixels, dans cet ordre :

1. **Amount : contraste et bruit.** Chaque canal de couleur est éloigné du gris moyen par un facteur de contraste allant jusqu'à 1,6×, puis un bruit aléatoire jusqu'à ±20 niveaux est ajouté et la valeur bornée entre 0 et 255.
2. **RGB shift.** Le tampon de pixels est copié ; pour chaque pixel, le rouge est lu sur un pixel situé *shift* colonnes à gauche et le bleu *shift* colonnes à droite, avec *shift* = RGB × 4 % de la largeur. Le vert ne bouge pas, d'où les franges rouges et bleues.
3. **Pixel sort.** Une colonne sur deux est parcourue de haut en bas. Là où la luminance (0,299 R + 0,587 V + 0,114 B, les pondérations Rec. 601) dépasse un seuil de 1 − Sort, la suite de pixels lumineux, limitée à la moitié de la hauteur × Sort, est collectée et réordonnée du plus sombre au plus clair.
4. **Scanlines.** Des lignes noires horizontales d'un pixel, tous les 2 à 4 pixels, sont dessinées par-dessus avec une opacité jusqu'à 50 %, comme sur un écran cathodique.
5. **Déchirures.** Quand Amount dépasse 25 %, jusqu'à huit fines bandes horizontales aléatoires sont copiées et décalées latéralement : la déchirure « tracking » typique du VHS.

Les préréglages ne sont que des positions de curseurs :

| Préréglage | Amount | RGB | Scanlines | Sort |
|---|---|---|---|---|
| VHS | 45 | 60 | 70 | 10 |
| Cyberpunk | 65 | 80 | 40 | 35 |
| Corrupt | 85 | 50 | 20 | 90 |
| Subtle | 20 | 25 | 15 | 5 |

Le rendu est planifié avec `requestAnimationFrame` : faire glisser un curseur redessine au plus une fois par image. Pour le téléchargement, un second canvas à la taille d'origine exécute la même chaîne d'effets puis est enregistré avec `toDataURL('image/png')`.

## Cas d'usage

- **Pochettes, affiches et miniatures** au look synthwave, VHS ou cyberpunk, sans ouvrir un éditeur lourd.
- **Publications sur les réseaux sociaux.** Une photo de profil « glitchée » ou un fond de story se remarque dans le fil.
- **Ressources pour jeux et applis.** Créez des fonds d'écran corrompus, des écrans d'erreur ou des textures d'interface « piratée ».
- **Exploration graphique.** Le pixel sorting et le décalage des canaux produisent vite des textures abstraites à partir de photos ordinaires.
- **Enseigner le traitement d'image.** Chaque curseur est une opération classique sur les pixels ; les activer un par un montre qu'une image n'est qu'un tableau de nombres.
