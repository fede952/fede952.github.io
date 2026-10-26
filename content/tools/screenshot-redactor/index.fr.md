---
title: "Masquer une capture d'écran : caviarder"
description: "Masquez e-mails, noms, IBAN et autres zones sensibles d'une capture d'écran. Rectangles pleins fondus dans les pixels, métadonnées retirées, dans le navigateur."
intro: "Collez une capture (Ctrl+V), déposez une image ou choisissez-la, puis **faites glisser pour couvrir** tout ce qui est sensible : adresses e-mail, noms, numéros de compte, visages, URL. Les masques sont des **rectangles pleins fondus dans les pixels** — aucun calque à retirer — et le PNG ou JPEG exporté **ne contient aucune métadonnée**. Une aide facultative peut **suggérer des zones** sur les e-mails, IBAN, numéros de carte et de téléphone et adresses IP. Rien n'est envoyé."
date: 2026-10-26
lastmod: 2026-10-26
reviewed: false
keywords: ["masquer capture d'écran", "caviarder une image", "cacher du texte sur une image", "flouter une capture d'écran", "pixeliser une image en ligne", "censurer une capture d'écran", "masquer des données personnelles", "noircir texte image"]
tags: ["confidentialité", "images", "sécurité", "tool"]
app_category: "MultimediaApplication"
tool_file: "/tools/screenshot-redactor/"
tool_title: "Masqueur de captures d'écran"
tool_height: 1050
tool_sandbox: "allow-scripts allow-same-origin allow-downloads"
tool_allow: "clipboard-write; clipboard-read"
howto:
  - "Collez une capture avec **Ctrl+V** (⌘V sur Mac), déposez une image sur la zone ou cliquez sur **Choisir une image**."
  - "Laissez **Rectangle plein** sélectionné (noir par défaut ; choisissez une autre **Couleur** si vous voulez) et faites glisser sur chaque zone à cacher. Sur téléphone, glissez avec un doigt et utilisez **Déplacer** pour faire défiler une image agrandie."
  - "Facultatif : cliquez sur **Suggérer des zones** pour trouver e-mails, IBAN, numéros de carte, numéros de téléphone et adresses IP grâce à la reconnaissance de texte sur l'appareil. Décochez les suggestions à garder visibles, puis **couvrez** les autres."
  - "Utilisez **Annuler** / **Rétablir** (Ctrl+Z / Ctrl+Y) et les boutons de zoom pour vérifier les bords de chaque rectangle."
  - "Choisissez **PNG** (texte net) ou **JPEG** (photos plus légères) et cliquez sur **Télécharger l'image masquée**, ou **Copier l'image** pour la coller directement dans une discussion ou un ticket."
faq:
  - q: "Mon image est-elle envoyée quelque part ?"
    a: "Non. L'image est décodée, modifiée et exportée dans votre navigateur. La reconnaissance de texte facultative fonctionne aussi sur votre appareil ; la première fois, elle télécharge ses fichiers (environ 10 Mo) depuis ce site, jamais depuis un tiers, et l'image elle-même n'est envoyée nulle part."
  - q: "Pourquoi un rectangle plein est-il plus sûr que le flou ou la pixellisation ?"
    a: "Un rectangle plein remplace les pixels par une seule couleur : il ne reste rien de l'original. Le flou et la pixellisation conservent une version réduite des pixels d'origine. Pour un texte court ou prévisible — chiffres, numéro de carte, nom dans une police connue —, cela suffit parfois à le reconstituer ou à le deviner, par exemple en floutant ou en pixellisant de la même façon des textes candidats et en comparant les résultats. Réservez-les à ce qui doit simplement attirer moins l'œil."
  - q: "Peut-on retirer le masquage du fichier téléchargé ?"
    a: "Non. L'export est une nouvelle image dessinée à partir des pixels modifiés : pas de calques, pas d'original caché, pas d'historique dans le fichier. C'est la différence avec un texte recouvert d'une forme dans un document ou un PDF, où le texte en dessous reste souvent sélectionnable."
  - q: "Les données EXIF et GPS sont-elles supprimées ?"
    a: "Oui. Le PNG ou JPEG exporté est encodé de zéro par le navigateur et ne contient aucune métadonnée : ni modèle d'appareil, ni date, ni position GPS. L'orientation de la photo est d'abord appliquée aux pixels, l'image reste donc dans le bon sens."
  - q: "Que trouve la suggestion automatique ?"
    a: "Les adresses e-mail, les IBAN (vérifiés par leur clé mod 97), les numéros de carte (vérifiés par l'algorithme de Luhn), les numéros de téléphone et les adresses IPv4 et IPv6. Elle fonctionne sur du texte d'écran en alphabet latin. Elle ne repère ni les noms, ni les visages, ni les adresses postales, ni l'écriture manuscrite : vérifiez toujours l'image vous-même avant de la partager."
  - q: "Quels formats d'image puis-je ouvrir ?"
    a: "Tous ceux que votre navigateur sait afficher : PNG, JPEG, WebP, GIF (première image) et généralement AVIF et BMP. Les photos HEIC d'un iPhone doivent d'abord être converties, par exemple avec le convertisseur HEIC de ce site."
---

## Comment ça marche

### Les masques sont des pixels, pas des calques

L'image est décodée dans un canvas en pleine résolution, en appliquant l'orientation EXIF de la photo. Chaque rectangle tracé est conservé comme une zone, et la composition image + rectangles est reconstruite à partir des pixels d'origine à chaque tracé, annulation ou rétablissement. À l'export, cette composition est encodée dans un PNG ou JPEG entièrement neuf. Le fichier ne contient que les pixels finaux : ce qui se trouvait sous un rectangle n'y existe plus.

C'est pourquoi les caviardages faits dans les traitements de texte échouent si souvent : un rectangle noir posé sur un texte dans un document ou un PDF est un objet à part, et le texte dessous peut encore être sélectionné ou extrait. Ici, il n'y a rien dessous.

### Pourquoi le flou et la pixellisation sont accompagnés d'un avertissement

La pixellisation remplace chaque bloc de pixels par sa couleur moyenne ; le flou étale chaque pixel sur ses voisins. Les deux suppriment de l'information, mais pas toute. Sur du texte, la forme de chaque lettre influence encore le résultat, et les originaux possibles sont souvent peu nombreux : un numéro de carte n'a que dix chiffres possibles par position, et les captures utilisent quelques polices connues. On peut écrire des textes candidats dans la même police, les pixelliser ou les flouter de la même manière et garder celui qui correspond. Des outils publics et des travaux de recherche ont montré que cela fonctionne sur des mots de passe et des numéros pixellisés. Un rectangle plein ne laisse rien à comparer : c'est le mode par défaut, et le seul recommandé pour ce qui est secret.

### Les suggestions facultatives

La reconnaissance de texte utilise Tesseract, un moteur d'OCR libre compilé en WebAssembly et servi par ce site. Il ne se charge que lorsque vous cliquez sur **Suggérer des zones**. Les mots reconnus sont comparés aux motifs des e-mails, IBAN, numéros de carte, numéros de téléphone et adresses IP ; IBAN et cartes doivent en plus passer leur clé de contrôle, ce qui limite les fausses alertes. Chaque correspondance devient un rectangle en pointillés que vous acceptez ou rejetez.

## Cas d'usage

- **Rapports de bug et tickets de support** — partagez la capture d'une erreur sans votre e-mail, votre identifiant de compte ou une clé d'API.
- **Réseaux sociaux et forums** — publiez une conversation ou un reçu avec les noms, numéros et références de commande masqués.
- **Documentation et tutoriels** — cachez les URL internes, adresses IP et données clients dans les captures de consoles d'administration.
- **Notes de frais** — envoyez la photo d'un ticket ou d'un virement avec le numéro de compte noirci.
- **Travail de sécurité** — insérez des preuves dans un rapport sans divulguer les identifiants ou les données personnelles qu'elles contiennent.
