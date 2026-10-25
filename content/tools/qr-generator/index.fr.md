---
title: "Générateur de QR Code Gratuit (PNG)"
description: "Créez des QR codes pour un lien ou un texte, réglez couleurs et correction d'erreur, téléchargez un PNG prêt à imprimer. Codes statiques sans expiration."
intro: "Saisissez un lien ou n'importe quel texte et obtenez un **QR code statique** à télécharger en PNG net et prêt à imprimer. Le code est généré dans votre navigateur, contient directement vos données et n'expire jamais. Les modes **Wi-Fi** et **Contact** créent des codes qui, en un seul scan, connectent à un réseau ou enregistrent une fiche de contact."
date: 2026-02-03
lastmod: 2026-10-25
reviewed: false
keywords: ["générateur de qr code", "créer un qr code gratuit", "qr code gratuit", "qr code pour un lien", "qr code png", "qr code sans inscription", "qr code statique", "qr code sans expiration"]
tags: ["qr-code", "utilitaires", "outil"]
app_category: "UtilitiesApplication"
tool_file: "/tools/qr-generator/"
tool_title: "QuickLinker, générateur de QR codes"
tool_height: 900
tool_sandbox: "allow-scripts allow-same-origin allow-downloads"
howto:
  - "Collez une URL (avec `https://`) ou tapez n'importe quel texte dans le champ. Les accents, les emoji et les alphabets non latins fonctionnent aussi."
  - "Pour un réseau, ouvrez **Wi-Fi** et saisissez le nom, le mot de passe et la sécurité ; pour une carte de visite, ouvrez **Contact** et remplissez les champs voulus. Le texte exact qui sera encodé apparaît sous **Texte encodé**."
  - "Choisissez si vous le souhaitez une couleur de **Premier Plan** et d'**Arrière-plan**. Gardez le premier plan nettement plus foncé que le fond, sinon beaucoup d'appareils photo de smartphone ne le liront pas."
  - "Choisissez le niveau de **Correction d'Erreur** : **M (15%)** par défaut ; prenez **Q** ou **H** si le code sera imprimé petit, en extérieur ou avec un logo par-dessus."
  - "Cliquez sur **Générer QR** et vérifiez l'aperçu en visant l'écran avec l'appareil photo de votre téléphone."
  - "Cliquez sur **Télécharger .PNG** pour enregistrer une image d'environ 1200 px avec la marge blanche requise, prête pour l'impression ou une présentation."
faq:
  - q: "Ces QR codes expirent-ils ?"
    a: "Non. Ce sont des QR codes statiques : votre lien ou votre texte est encodé dans le motif lui-même. Ils ne pointent vers aucun serveur à nous ; il n'y a donc rien à désactiver, aucun abonnement et aucune limite de scans. La contrepartie : impossible de changer la destination ensuite. Si l'URL change, générez un nouveau code."
  - q: "Ce générateur de QR codes est-il vraiment gratuit ?"
    a: "Oui, sans compte, sans filigrane et sans limite de nombre. La page est financée par les publicités affichées autour de l'outil, pas par des fonctions verrouillées."
  - q: "Quelle différence entre un QR code statique et un QR code dynamique ?"
    a: "Un QR code dynamique contient un lien court vers le serveur du fournisseur, qui redirige vers votre vraie URL. Le fournisseur peut ainsi compter les scans et changer la destination, mais le code cesse de fonctionner si vous arrêtez de payer ou si le service ferme, et chaque scan passe par ses serveurs. Un code statique, comme ceux créés ici, mène directement à votre URL."
  - q: "Quel niveau de correction d'erreur choisir ?"
    a: "L récupère environ 7 % des modules abîmés, M 15 %, Q 25 % et H 30 %. Les niveaux élevés rendent le code plus dense pour un même contenu. M convient aux écrans et aux impressions propres ; choisissez Q ou H pour de petits autocollants, des surfaces rugueuses ou un logo au centre."
  - q: "Combien de texte tient dans un QR code ?"
    a: "Le générateur choisit automatiquement la plus petite des 40 versions QR qui contient le texte. Au niveau M, un code de version 40 contient environ 2 300 octets de texte, mais des codes aussi grands sont difficiles à scanner avec un téléphone. Pour les liens, plus c'est court, mieux c'est : une URL de 30 à 60 caractères donne un code net et facile à lire."
  - q: "Pourquoi mon QR code en couleur ne se scanne-t-il pas ?"
    a: "Les lecteurs cherchent des modules foncés sur fond clair avec un contraste suffisant. Les couleurs inversées (clair sur foncé), les paires peu contrastées comme le jaune sur blanc ou une image derrière le code sont les causes habituelles. Du noir ou une couleur foncée sur blanc reste le choix le plus sûr."
  - q: "Ce que je saisis est-il envoyé quelque part ?"
    a: "Non. Le QR code est calculé par une bibliothèque JavaScript exécutée dans cette page puis dessiné sur un canvas. Rien n'est envoyé, ce qui compte si vous encodez un mot de passe Wi-Fi, une URL interne ou une note privée."
  - q: "Comment fonctionne un QR code Wi-Fi ?"
    a: "Il contient un court texte au format `WIFI:` que les appareils photo Android et iPhone reconnaissent, par exemple `WIFI:T:WPA;S:Maison;P:secret;;`. En le scannant, le téléphone propose de se connecter sans taper le mot de passe. Les caractères spéciaux du nom ou du mot de passe (`\\ ; , : \"`) sont précédés d'une barre oblique inverse, comme l'exige le format : un mot de passe comme `p;ss:word` fonctionne donc aussi. Toute personne qui scanne le code peut lire le mot de passe : ne l'imprimez que là où les invités sont les bienvenus."
  - q: "Quel format est utilisé pour les contacts et que peut-il contenir ?"
    a: "Une vCard 3.0, la version que les appareils photo des téléphones importent le plus fiablement : nom, organisation, fonction, mobile, e-mail, site web, adresse et une note. Les champs vides sont omis pour garder un code compact. Virgules, points-virgules et retours à la ligne sont échappés comme l'exige la norme vCard. Une fiche complète donne un code dense : laissez de côté ce qui est inutile et gardez la correction d'erreur sur L ou M."
---

## Comment ça marche

L'outil s'appuie sur la bibliothèque open source **qrcode-generator** de Kazuhiko Arase (v1.4.4, hébergée sur ce site) et dessine le résultat sur un canvas HTML.

1. **Encodage.** Votre texte est converti en octets **UTF-8** et stocké en *mode octet* : `é`, `à`, `ç`, `€` et les emoji ressortent exactement comme vous les avez tapés quand un téléphone les lit. (Par défaut, la bibliothèque ne garderait qu'un octet par caractère et abîmerait tout ce qui sort du latin de base ; la page la règle donc explicitement sur UTF-8.)
2. **Choix de la version.** La bibliothèque choisit la plus petite **version QR**, de la version 1 (21 × 21 modules) à la version 40 (177 × 177), capable de contenir vos données au niveau de correction choisi.
3. **Correction d'erreur.** Les QR codes ajoutent des mots de correction **Reed-Solomon** pour qu'un lecteur puisse reconstruire des parties manquantes ou salies : le niveau **L** récupère ~7 %, **M** ~15 %, **Q** ~25 % et **H** ~30 % des mots de code.
4. **Dessin.** Chaque module foncé est dessiné comme un carré de la couleur de premier plan. Autour du symbole, l'outil laisse une **zone de silence de 4 modules** dans la couleur de fond, la marge exigée par la norme QR (ISO/IEC 18004) ; sans elle, les lecteurs peinent dès que le code est posé sur une page colorée.
5. **Export.** L'aperçu à l'écran fait environ 300 px. Au téléchargement, le code est redessiné à environ **1200 px**, chaque module faisant un nombre entier de pixels pour garder des bords nets, puis enregistré sous `qrcode.png`.

| Contenu | Longueur typique | Version au niveau M | Modules |
|---|---|---|---|
| URL courte | 25 caractères | 2 | 25 × 25 |
| URL normale avec chemin | 60 caractères | 4 | 33 × 33 |
| URL longue avec paramètres de suivi | 150 caractères | 8 | 49 × 49 |
| Un paragraphe de texte | 500 caractères | 17 | 85 × 85 |

Moins il y a de modules, plus chacun est grand une fois imprimé et plus le code se lit facilement de loin : retirer les paramètres de suivi d'une URL compte donc souvent davantage que le niveau de correction.

### Codes Wi-Fi et contact

En mode **Wi-Fi**, l'outil écrit `WIFI:T:<WPA|WEP|nopass>;S:<réseau>;P:<mot de passe>;H:true;;` (le champ `H` seulement pour les réseaux masqués) ; `WPA` couvre WPA, WPA2 et WPA3 Personnel, car le téléphone négocie la version exacte. En mode **Contact**, il écrit une vCard 3.0 avec des fins de ligne CRLF. Les deux formats sont testés en décodant le PNG téléchargé et en comparant le résultat caractère par caractère, y compris avec des noms et mots de passe pleins de `; , : " \`.

## Cas d'usage

- **Impression et emballages.** Un QR code sur des flyers, cartes de visite, menus ou étiquettes qui ouvre votre site, une page d'avis ou une notice. Un code statique fonctionne tant que l'URL fonctionne.
- **Présentations et affiches.** Le public ouvre vos diapositives, un sondage ou un dépôt sans taper une longue adresse.
- **Partager du texte hors ligne.** Encodez une courte note, un numéro de série ou des coordonnées qu'un téléphone peut lire sans réseau.
- **Tester vos propres applis.** Générez des codes pour des liens profonds, des URL de préproduction ou des tests de callback OAuth sans coller d'adresses internes dans un service tiers.
- **Sensibilisation à la sécurité.** Le « quishing » (hameçonnage par QR code) cache des liens malveillants derrière des codes. Générer les vôtres permet de montrer à vos collègues à quel point un code peut pointer n'importe où, et pourquoi il faut regarder l'URL affichée par le téléphone avant de toucher.
