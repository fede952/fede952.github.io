---
title: "Test d'Empreinte du Navigateur"
description: "Voyez l'empreinte que votre navigateur livre à chaque site (canvas, GPU WebGL, audio, polices, écran, fuseau horaire) et un score d'unicité estimé."
intro: "**GhostPrint** lit les mêmes signaux que les scripts de pistage et d'anti-fraude lisent en silence sur la plupart des sites, vous les montre un par un et estime à quel point ils rendent votre navigateur identifiable. Chaque mesure s'exécute dans cette page ; rien n'est envoyé."
date: 2026-07-06
lastmod: 2026-10-24
reviewed: false
keywords: ["test empreinte navigateur", "browser fingerprinting", "empreinte numérique navigateur", "canvas fingerprint", "webgl fingerprint", "suis-je traçable", "suis-je unique en ligne", "pistage sans cookies"]
tags: ["vie privée", "sécurité", "fingerprinting", "outil"]
app_category: "SecurityApplication"
tool_file: "/tools/ghostprint/"
tool_title: "GhostPrint, test d'empreinte du navigateur"
tool_height: 2200
tool_settle_ms: 3000
tool_sandbox: "allow-scripts allow-same-origin allow-downloads allow-modals"
tool_allow: "clipboard-write"
howto:
  - "Ouvrez la page : l'analyse démarre toute seule. GhostPrint mesure 12 signaux en deux secondes environ et les affiche au fur et à mesure ; **Re-scan** la relance."
  - "Lisez le verdict et le chiffre principal, par exemple « 1 in 2.1 million » : le nombre estimé de navigateurs qu'il faudrait examiner avant d'en trouver un avec la même empreinte."
  - "Parcourez les cartes de signaux : chacune affiche la valeur brute, les bits d'information identifiante qu'elle apporte et une explication en une ligne."
  - "Notez votre **Fingerprint ID**. Ouvrez cette page en navigation privée ou après avoir effacé vos cookies : l'ID ne change pas, et c'est tout le principe du fingerprinting."
  - "Utilisez **Download shareable card** ou **Copy summary** pour comparer des navigateurs ou montrer à un collègue pourquoi effacer les cookies ne suffit pas."
faq:
  - q: "Qu'est-ce que le browser fingerprinting ?"
    a: "C'est une façon de reconnaître un navigateur sans rien y stocker. Un script lit des dizaines de petites propriétés (taille d'écran, polices installées, modèle de GPU, manière dont votre machine dessine une image cachée) et les combine en un identifiant. Aucun cookie n'intervient : l'identifiant survit donc à la navigation privée, à l'effacement des cookies et à la plupart des boutons « effacer les données »."
  - q: "Le score d'unicité est-il une mesure ?"
    a: "C'est une estimation. Chaque signal reçoit un poids fixe en bits, selon la quantité d'information identifiante que ce type de signal porte en général d'après la recherche publiée sur le fingerprinting ; les poids sont additionnés, réduits de 18 % parce que les signaux sont corrélés, et le résultat est plafonné à environ 5,5 milliards, le nombre d'internautes. GhostPrint ne vous compare pas à une base de données d'autres visiteurs : c'est ce qui lui permet de fonctionner sans rien collecter."
  - q: "La navigation privée empêche-t-elle le fingerprinting ?"
    a: "Non. La navigation privée efface cookies et historique à la fermeture, mais votre GPU, vos polices, votre écran et le rendu du canvas restent identiques, donc l'empreinte aussi. Vous pouvez le vérifier : le Fingerprint ID affiché ici ne change pas dans une fenêtre privée."
  - q: "Quels navigateurs résistent le mieux au fingerprinting ?"
    a: "Tor Browser rend tous ses utilisateurs identiques, l'approche la plus efficace. Brave rend aléatoires, site par site, les lectures du canvas, de WebGL et de l'audio. Firefox propose `privacy.resistFingerprinting`, qui uniformise de nombreuses valeurs. Safari réduit certains signaux par défaut. Chrome et Edge en exposent la plupart, sauf extension."
  - q: "Les extensions anti-fingerprinting sont-elles utiles ?"
    a: "Certaines oui, surtout celles qui rendent aléatoires le canvas et l'audio, mais une extension rare peut elle-même devenir un trait distinctif. Bloquer complètement un signal, comme WebGL, peut aussi vous rendre plus singulier. Le but est de paraître ordinaire, pas invisible."
  - q: "Mes données sont-elles envoyées à votre serveur ?"
    a: "Non. Toutes les mesures tournent en JavaScript dans cette page et le résultat est affiché localement. L'outil n'interroge aucun service d'analyse ou de fingerprinting, et la carte téléchargeable est générée sur un canvas dans votre navigateur."
---

## Comment ça marche

GhostPrint recueille douze signaux. Cinq sont *mesurés* activement en dessinant ou en calculant quelque chose ; les autres sont lus via des API standard du navigateur.

**Signaux de rendu**

- **Canvas.** La page dessine du texte (avec un emoji et des lettres accentuées), un rectangle plein et un arc sur un canvas caché de 240 × 60, l'exporte avec `toDataURL()` et en calcule un hash FNV-1a sur 32 bits. Les polices, l'anticrénelage, le GPU et le pilote graphique laissent d'infimes différences de pixels : le hash varie d'une machine à l'autre. Une sortie vide ou minuscule est considérée comme bloquée.
- **WebGL.** Il ouvre un contexte WebGL, lit le fabricant et le moteur de rendu du GPU non masqués via `WEBGL_debug_renderer_info`, et les combine dans un hash avec la version de WebGL, celle du langage de shaders, les tailles maximales de texture et de renderbuffer, la limite d'attributs de sommets et la liste complète des extensions prises en charge.
- **Audio.** Un `OfflineAudioContext` calcule une seconde d'onde triangulaire à 10 kHz passée dans un compresseur dynamique. La somme de 1 000 échantillons de sortie est hachée ; les différences de calcul en virgule flottante d'une pile audio à l'autre la font varier selon l'appareil. Au bout de 900 ms, la mesure abandonne.
- **Polices.** Une chaîne de test cachée de 72 px est mesurée dans les trois familles génériques (serif, sans-serif, monospace), puis à nouveau avec chacune de **53 polices courantes** placée en tête. Si la largeur ou la hauteur change, la police est installée. Votre jeu de polices reflète votre système, sa langue et les logiciels installés.

**Signaux lus directement :** chaîne user-agent, plateforme, résolution d'écran avec ratio de pixels et profondeur de couleur, fuseau horaire avec décalage UTC, langues préférées, cœurs du processeur, mémoire de l'appareil et points tactiles, préférences de thème et de mouvement réduit, et état des cookies, de Do-Not-Track et de Global Privacy Control.

### Des signaux au « 1 sur N »

Chaque signal a un poids fixe en bits :

| Signal | Bits |
|---|---|
| Empreinte canvas | 8 |
| Polices | 0,45 par police détectée, max 8 |
| Modèle de GPU (WebGL) | 7 |
| User agent | 6 (8 s'il est inhabituellement long) |
| Empreinte audio | 5 |
| Écran, fuseau horaire | 2 chacun |
| Langues, matériel | 1,5 chacun |
| Plateforme | 1 |
| Préférences d'affichage, indicateurs de confidentialité | 0,5 chacun |

Un signal bloqué ou rendu aléatoire compte pour 0 bit. Le total est multiplié par **0,82** pour tenir compte de la corrélation (un GPU donné implique souvent une plateforme donnée, par exemple), puis converti en « 1 sur 2^bits », plafonné à 5,5 milliards. Les verdicts sont *Blending in* sous 10 bits, *Identifiable* dès 10, *Highly unique* dès 18 et *Ghost-level exposure* dès 28.

Le **Fingerprint ID** est formé de trois hashes FNV-1a de 4 caractères : du user agent, de la plateforme et de l'écran ; des hashes WebGL et canvas ; et de tous les signaux réunis. Sa stabilité en navigation privée en est la démonstration concrète.

## Cas d'usage

- **Comprendre pourquoi « effacer les cookies » ne protège pas.** Faites le test, effacez tout, refaites-le : même ID.
- **Comparer navigateurs et réglages.** Essayez Firefox avec `resistFingerprinting`, Brave, Tor Browser et votre navigateur habituel, et regardez quelles cartes tombent à 0 bit.
- **Sensibilisation à la sécurité.** Une démo de 30 secondes des cartes GPU et polices rend le concept concret, même pour des collègues non techniques.
- **Vérifier des hypothèses anti-fraude.** Les équipes qui conçoivent du scoring de risque voient quels signaux sont stables et lesquels se bloquent facilement.
- **Partager le résultat.** La carte téléchargeable de 1200 × 630 (format d'aperçu pour les réseaux sociaux) affiche votre verdict, votre entropie et votre ID sans exposer les valeurs brutes.
