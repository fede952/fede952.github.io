---
title: "Supprimer EXIF et GPS d'une Photo"
description: "Voyez les métadonnées EXIF cachées d'une photo (position GPS, appareil, date) et téléchargez une copie nettoyée. Fonctionne hors ligne, sans aucun envoi."
intro: "**EXIF Cleaner** affiche les métadonnées cachées dans une photo (coordonnées GPS, modèle d'appareil, date de prise de vue, logiciel) et vous donne une copie propre débarrassée de tout cela. L'image ne quitte jamais votre appareil."
date: 2026-02-03
lastmod: 2026-10-24
reviewed: false
keywords: ["supprimer données exif", "supprimer métadonnées photo", "enlever gps photo", "supprimer localisation image", "lecteur exif", "effacer exif en ligne", "métadonnées photo", "nettoyer métadonnées"]
tags: ["vie privée", "osint", "images", "outil"]
app_category: "SecurityApplication"
tool_file: "/tools/exif-cleaner/"
tool_title: "EXIF Cleaner : voir et supprimer les métadonnées"
tool_height: 820
tool_sandbox: "allow-scripts allow-same-origin allow-downloads"
howto:
  - "Glissez une photo dans la zone de dépôt ou cliquez pour en choisir une. Le JPEG fonctionne le mieux ; le PNG et le WebP sont aussi acceptés."
  - "Lisez le tableau **Métadonnées Trouvées** : marque et modèle de l'appareil, date de prise de vue, logiciel, exposition, ISO, focale, orientation, dimensions, copyright, auteur et coordonnées GPS."
  - "Si un avertissement rouge apparaît, la photo contient une **position GPS**. Les coordonnées décimales affichées indiquent le lieu de la prise de vue, à quelques mètres près."
  - "Cliquez sur **Supprimer Métadonnées et Télécharger**. L'image est redessinée sans aucune métadonnée et enregistrée dans le même format."
  - "Cliquez sur **Télécharger l’Image Nettoyée** pour enregistrer `votrefichier-clean.jpg` (ou .png/.webp), et partagez cette copie plutôt que l'original."
faq:
  - q: "Que sont les données EXIF ?"
    a: "L'EXIF (Exchangeable Image File Format) est un bloc de métadonnées que les appareils photo et les téléphones inscrivent dans chaque photo : marque et modèle, objectif, réglages d'exposition, date et heure, logiciel de retouche et souvent les coordonnées GPS du lieu de prise de vue. Invisible quand on regarde l'image, mais lisible en un instant avec un outil comme celui-ci."
  - q: "Les réseaux sociaux suppriment-ils l'EXIF automatiquement ?"
    a: "Les grandes plateformes comme Facebook, Instagram, X et WhatsApp retirent la plupart des métadonnées des images publiées. Les pièces jointes d'e-mail, les liens de stockage en ligne, les forums, les sites de petites annonces, les applis de rencontre et beaucoup de messageries en envoi « comme fichier » ou « qualité originale » ne le font pas. Dans le doute, nettoyez d'abord la photo."
  - q: "Ma photo est-elle envoyée en ligne pour retirer les métadonnées ?"
    a: "Non. La lecture des métadonnées et la création de la copie propre se font en JavaScript dans cette page. Vous pouvez couper internet après le chargement, l'outil continue de fonctionner : il convient donc aussi aux photos sensibles."
  - q: "Le nettoyage dégrade-t-il la qualité de l'image ?"
    a: "La sortie PNG est sans perte. Le JPEG et le WebP sont réencodés en qualité 95, visuellement indiscernable de l'original pour presque toutes les photos ; le poids du fichier peut varier légèrement. La résolution reste exactement la même."
  - q: "Pourquoi mon PNG ou WebP n'affiche-t-il aucune métadonnée ?"
    a: "Le lecteur utilise exif-js, qui lit le bloc EXIF des fichiers JPEG. Le PNG et le WebP stockent leurs métadonnées autrement et contiennent rarement du GPS ; le tableau peut donc rester vide. La copie propre est malgré tout réencodée à partir des pixels, si bien que leurs éventuelles métadonnées disparaissent aussi."
  - q: "La photo nettoyée sera-t-elle toujours dans le bon sens ?"
    a: "Oui. Les téléphones enregistrent souvent les photos de côté et comptent sur la balise EXIF Orientation pour les faire pivoter. Le navigateur applique cette rotation en dessinant l'image : la copie propre a donc la bonne orientation directement dans ses pixels et n'a plus besoin de la balise."
  - q: "Peut-on récupérer les métadonnées supprimées à partir de la copie propre ?"
    a: "Non. Le fichier nettoyé est une nouvelle image construite uniquement à partir des pixels ; le bloc de métadonnées d'origine n'y est jamais recopié. Gardez l'original si vous voulez conserver la date et le lieu pour votre photothèque."
---

## Comment ça marche

### Lecture des métadonnées

Quand vous déposez un fichier, la page le lit localement avec `FileReader` et le transmet à **exif-js** (v2.3.0, hébergée ici). La bibliothèque parcourt le segment APP1 du JPEG et décode les répertoires EXIF à structure TIFF : le répertoire principal de l'image (marque, modèle, logiciel, orientation, copyright, auteur), le sous-répertoire Exif (temps de pose, ouverture, ISO, focale, flash, dimensions en pixels, espace colorimétrique) et le répertoire GPS.

Les coordonnées GPS sont stockées en degrés, minutes et secondes avec une référence d'hémisphère (N/S, E/W). L'outil les convertit en degrés décimaux, `degrés + minutes/60 + secondes/3600`, négatifs pour le sud et l'ouest, et les affiche avec six décimales, soit environ 10 cm de précision. Si une position GPS est présente, l'avertissement rouge s'affiche.

### Création de la copie propre

Les métadonnées ne sont pas retirées octet par octet : l'outil jette tout le conteneur.

1. Le navigateur décode l'image en pixels bruts.
2. Ces pixels sont dessinés en pleine résolution sur un `<canvas>` HTML. Au passage, le navigateur applique l'orientation EXIF : le résultat est à l'endroit.
3. Le canvas est encodé dans un tout nouveau fichier avec `canvas.toBlob()` : **JPEG en qualité 0,95** pour un JPEG, **WebP en 0,95** pour un WebP et **PNG** pour tout le reste.

Un canvas ne contient que des pixels : le nouveau fichier n'a donc **ni EXIF, ni GPS, ni balises XMP ou IPTC, ni miniature intégrée** (les anciennes miniatures montrent parfois encore l'original *non recadré*), ni profil colorimétrique. Les images sortent en sRGB, si bien que les photos à large gamut peuvent paraître très légèrement moins saturées.

Pour vérifier, déposez à nouveau le fichier `-clean` téléchargé dans l'outil : le tableau sera vide et l'avertissement GPS n'apparaîtra pas.

### Ce qu'il ne touche pas

La copie propre supprime les *métadonnées*, pas ce qui est visible sur la photo. Un panneau de rue, un reflet dans une vitrine, une plaque d'immatriculation ou un monument reconnaissable peuvent encore révéler le lieu. Recadrez ou floutez ces éléments avant de partager.

## Cas d'usage

- **Vendre en ligne.** Les photos d'objets prises chez vous peuvent contenir les coordonnées GPS de votre domicile. Nettoyez-les avant de les mettre sur un site de petites annonces.
- **Envoyer des photos à des personnes que vous connaissez peu**, comme un propriétaire, un contact sur une appli de rencontre ou un acheteur, sans livrer votre adresse ni votre modèle de téléphone.
- **Journalisme et militantisme.** Retirez la localisation et les détails de l'appareil des images qui pourraient identifier une source.
- **Vérifier ce que vous partagez.** Ouvrez une photo et voyez exactement ce qu'elle révèle ; voir sa propre rue sur une carte fait toujours son effet la première fois.
- **S'entraîner à l'OSINT.** Les enquêteurs se servent de l'EXIF comme d'une piste. Utilisez le lecteur sur des images d'exemple pour comprendre ce qui peut être extrait et pourquoi nettoyer compte.
