---
title: "JPG en PDF : convertir des images en PDF"
description: "Réunissez des images JPG, PNG et WebP en un seul PDF dans le navigateur : réordonnez, pivotez, choisissez A4, Lettre ou taille de l'image et marges. Sans envoi."
intro: "Transformez photos, numérisations et captures d'écran en un seul **PDF** : déposez des images **JPG, PNG, WebP ou GIF**, mettez-les dans l'ordre, faites pivoter celles qui sont de travers, choisissez **A4, Lettre US ou la taille de l'image** et une marge, puis téléchargez. Les images sont traitées dans cet onglet et leurs données EXIF et GPS ne se retrouvent jamais dans le PDF."
date: 2026-10-25
lastmod: 2026-10-25
reviewed: false
keywords: ["jpg en pdf", "convertir jpg en pdf", "image en pdf", "png en pdf", "photos en pdf", "regrouper des images en pdf", "jpg en pdf sans envoi", "webp en pdf"]
tags: ["pdf", "images", "confidentialité", "tool"]
app_category: "UtilitiesApplication"
tool_file: "/tools/images-to-pdf/"
tool_title: "Convertisseur d'images en PDF"
tool_height: 760
tool_sandbox: "allow-scripts allow-same-origin allow-downloads"
howto:
  - "Déposez vos images dans le cadre ou cliquez pour les choisir. Chaque image devient une page ; vous pouvez en ajouter à tout moment."
  - "Mettez les pages dans l'ordre en faisant glisser les miniatures ou avec **←** et **→**. **⟳** fait pivoter une image de 90°, **✕** la retire."
  - "Choisissez le **Format de page** : **A4**, **Lettre US** ou **Comme l'image** pour des pages qui correspondent exactement à chaque photo."
  - "En A4 ou Lettre, l'orientation **Automatique (par image)** place les images larges sur des pages paysage et les hautes sur des pages portrait ; vous pouvez forcer **Portrait** ou **Paysage**. Choisissez une **Marge** (aucune, 1 cm ou 2 cm)."
  - "Indiquez le **Nom du fichier** et cliquez sur **Créer le PDF et télécharger**."
faq:
  - q: "Mes images sont-elles envoyées ?"
    a: "Non. Le navigateur décode les images, les dessine sur un canvas et pdf-lib les place dans un PDF, le tout dans cet onglet. Rien n'est envoyé à un serveur, ce qui compte pour les pièces d'identité, les reçus et les documents médicaux."
  - q: "Le PDF garde-t-il la position ou les données d'appareil de mes photos ?"
    a: "Non. Chaque image est redessinée sur un canvas avant d'être intégrée, et un canvas ne porte aucune métadonnée : les champs EXIF comme la position GPS, la date ou le modèle d'appareil ne sont pas dans le PDF. Le PDF ne reçoit que des métadonnées techniques de base de la bibliothèque."
  - q: "Pourquoi mes photos de téléphone sont-elles dans le bon sens ?"
    a: "Les téléphones enregistrent souvent les photos couchées et notent la bonne rotation dans une balise EXIF. L'outil lit l'image avec cette orientation déjà appliquée avant de la dessiner : la page ressemble donc à la photo de votre galerie. Utilisez ⟳ si une numérisation est encore tournée."
  - q: "Les images perdent-elles en qualité ?"
    a: "Les photos sont réencodées en JPEG de haute qualité (92 %), visuellement identique pour l'impression et les documents. Les images PNG, WebP et GIF sont stockées sans perte en PNG, ce qui garde les textes nets et les zones transparentes."
  - q: "Quelle sera la taille du PDF ?"
    a: "À peu près celle des images ajoutées. Des photos très lourdes donnent un PDF lourd ; si le fichier doit rester léger pour un formulaire, compressez d'abord les photos, par exemple avec un compresseur d'images, puis convertissez."
  - q: "Puis-je convertir des photos HEIC d'iPhone ?"
    a: "La plupart des navigateurs ne lisent pas le HEIC directement. Convertissez d'abord les photos en JPG avec le convertisseur HEIC de ce site — lui aussi hors ligne dans le navigateur — puis ajoutez les JPG ici."
  - q: "Que signifie « Comme l'image » ?"
    a: "La page a la taille de la photo à 96 pixels par pouce, plus la marge. C'est le meilleur choix pour les captures d'écran et les dessins qui ne doivent pas être redimensionnés sur un format papier."
---

## Comment ça marche

### De l'image à la page

Pour chaque image, l'outil :

1. La décode avec `createImageBitmap(file, { imageOrientation: 'from-image' })`, afin de respecter l'orientation EXIF des photos de téléphone.
2. La dessine sur un `<canvas>` en appliquant votre rotation et la réencode : en **JPEG à 92 % de qualité** pour les photos JPG, ou en **PNG** pour les sources PNG, WebP et GIF, afin de garder transparences et contours nets. Pour les GIF, la première image est utilisée.
3. Intègre le résultat dans le PDF avec **pdf-lib** (`embedJpg` / `embedPng`).

### Mise en page

L'A4 mesure 595 × 842 points et la Lettre US 612 × 792 points (1 point = 1/72 de pouce). L'image est mise à l'échelle pour tenir dans la page moins la marge de chaque côté, en gardant ses proportions, et centrée. En orientation automatique, la page passe en paysage dès que l'image est plus large que haute. Avec **Comme l'image**, la page fait la taille de l'image à 96 DPI — une capture de 1920 × 1080 donne une page de 1440 × 810 points — plus la marge.

### Bibliothèques

pdf-lib (MIT) n'est chargée depuis ce site qu'au moment de créer le PDF ; la grille de miniatures utilise le décodage d'images du navigateur. Rien n'est demandé à des serveurs tiers.

## Cas d'usage

- **Envoyer des numérisations de documents papier** — reçus, contrats, devoirs — en un seul PDF que tout bureau peut ouvrir.
- **Déposer des pièces d'identité ou des bulletins de paie** dans un formulaire qui n'accepte que le PDF, sans passer d'abord par un convertisseur en ligne.
- **Créer un portfolio ou un album** de JPG dans l'ordre de votre choix.
- **Archiver des captures d'écran** d'une configuration, d'une erreur ou d'une conversation dans un seul fichier daté.
- **Préparer des pages prêtes à imprimer** en A4 ou Lettre avec des marges régulières.
