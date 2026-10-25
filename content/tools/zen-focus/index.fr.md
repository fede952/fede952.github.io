---
title: "Minuteur de Concentration & Bruit Blanc"
description: "Mixez bruit blanc, rose et brun, pluie, feu de cheminée, clavier et café, et lancez un minuteur Pomodoro. Sons générés en direct dans votre navigateur."
intro: "**ZenFocus** associe un minuteur de concentration à une table de mixage d'ambiances à huit canaux. Choisissez un preset ou composez votre mélange de bruit, pluie, cheminée, clavier et brouhaha de café, puis lancez une session de 25 minutes. Chaque son est généré en direct dans votre navigateur : aucun fichier audio, aucun compte."
date: 2026-02-03
lastmod: 2026-10-24
reviewed: false
keywords: ["minuteur concentration", "minuteur pomodoro en ligne", "mixeur de sons d'ambiance", "bruit brun", "bruit blanc en ligne", "bruit rose", "bruit de pluie pour étudier", "bruit de fond pour se concentrer"]
tags: ["productivité", "concentration", "audio", "outil"]
app_category: "UtilitiesApplication"
tool_file: "/tools/zen-focus/"
tool_title: "ZenFocus, minuteur et mixeur de bruits"
tool_height: 800
tool_sandbox: "allow-scripts allow-same-origin allow-popups allow-popups-to-escape-sandbox"
tool_allow: "clipboard-write; web-share"
howto:
  - "Choisissez un preset : **Deep Work** (bruit brun et pluie), **Coffee Break** (brouhaha de café et cheminée) ou **Silence** pour couper tous les canaux."
  - "Ou composez votre mélange avec le curseur de chaque carte. Le bouton 🔊 d'une carte coupe ce canal sans perdre son niveau."
  - "Réglez le volume général avec le curseur **Master**. Commencez bas : un bruit de masquage fonctionne mieux s'il couvre tout juste les distractions."
  - "Réglez la durée avec **−5**, **−1**, **+1** et **+5** (de 1 à 90 minutes, 25 par défaut), puis appuyez sur **Start**."
  - "Travaillez jusqu'au carillon. **Pause** arrête l'horloge et **Reset** rétablit la durée complète. Pour une pause, réglez 5 minutes et relancez."
faq:
  - q: "Quelle différence entre bruit blanc, rose et brun ?"
    a: "La répartition de l'énergie selon les fréquences. Le bruit blanc a la même puissance à toutes les fréquences et sonne comme un souffle aigu. Le rose perd environ 3 dB par octave : il est plus doux, proche d'une pluie régulière. Le brun (brownien) perd environ 6 dB par octave et évoque un grondement grave ou une cascade lointaine. Beaucoup trouvent le rose et le brun moins fatigants que le blanc sur de longues sessions."
  - q: "Le bruit de fond améliore-t-il vraiment la concentration ?"
    a: "Les études sont partagées. Un bruit continu masque de façon fiable les sons imprévisibles, comme les conversations et les notifications, qui sont ce qui casse le plus souvent la concentration. Certaines études rapportent un bénéfice pour l'attention, notamment chez les personnes avec un TDAH ; d'autres ne trouvent aucun effet, voire un coût pour la lecture complexe. Voyez-le comme une expérience personnelle : essayez un mélange une semaine et gardez-le s'il vous aide."
  - q: "Qu'est-ce que la technique Pomodoro ?"
    a: "Une méthode de gestion du temps créée par Francesco Cirillo : 25 minutes de travail sur une tâche, 5 minutes de pause et, après quatre cycles, une pause plus longue de 15 à 30 minutes. ZenFocus démarre à 25 minutes ; pour les pauses, réglez 5. Il ne bascule pas automatiquement, vous décidez donc quand commence le cycle suivant."
  - q: "Le minuteur continue-t-il dans un onglet en arrière-plan ?"
    a: "Oui. Le compte à rebours est calculé à partir d'une heure de fin fixe, et non en comptant des ticks, il reste donc précis même quand le navigateur ralentit les minuteurs des onglets masqués. Le carillon sonne à la fin, tant que l'onglet est ouvert."
  - q: "Pourquoi n'y a-t-il aucun son avant que je clique ?"
    a: "Les navigateurs bloquent l'audio tant que vous n'avez pas interagi avec la page. ZenFocus démarre son moteur audio à votre premier clic sur un curseur, un preset ou Start, puis fait monter les canaux en douceur."
  - q: "Les sons sont-ils des enregistrements ?"
    a: "Non. Chaque canal est synthétisé avec la Web Audio API : des tampons de bruit façonnés par des filtres (la pluie est par exemple un bruit blanc passe-haut et le tonnerre un bruit brun passe-bas), et le clavier est une suite de clics brefs aléatoires. Rien n'est téléchargé ni diffusé : une fois la page chargée, cela fonctionne aussi hors ligne."
  - q: "Peut-on écouter pendant des heures sans risque ?"
    a: "Gardez un volume modéré. Une règle courante : rester à un niveau où vous entendez encore quelqu'un vous parler à côté, et faire des pauses régulières. Une exposition prolongée à un son fort au casque peut abîmer l'audition."
---

## Comment ça marche

ZenFocus est une page unique basée sur la **Web Audio API**. À la première interaction, elle crée un `AudioContext` et génère en mémoire quelques secondes de bruit brut :

- **Bruit blanc** : échantillons aléatoires uniformes entre −1 et 1, d'où un spectre plat.
- **Bruit rose** : le célèbre filtre de Paul Kellet, un banc de filtres du premier ordre qui approche une pente de −3 dB/octave.
- **Bruit brun** : un « intégrateur à fuite » qui cumule des pas aléatoires, pour une pente de −6 dB/octave.
- **Clics de clavier** : environ cinq impulsions brèves par seconde, à décroissance exponentielle et volume aléatoire.

Les tampons rose et brun sont corrigés pour que leur dernier échantillon rejoigne le premier, afin que le point de boucle ne claque pas. Chacun des huit canaux est une source en boucle, éventuellement filtrée par un biquad, puis un nœud de gain (le curseur de la carte) et enfin le gain master :

| Canal | Source | Filtre |
|---|---|---|
| White Noise | blanc | aucun |
| Pink Noise | rose | aucun |
| Brown Noise | brun | aucun |
| Rain | blanc | passe-haut 1,2 kHz |
| Thunder | brun | passe-bas 100 Hz |
| Fireplace | blanc | passe-bande 700 Hz |
| Keyboard | clics | passe-bande 2,2 kHz |
| Coffee Shop | rose | passe-bande large 1 kHz |

Tous les canaux tournent dès le départ ; un curseur ne modifie que son gain, avec une rampe de 50 ms pour éviter tout claquement. La sourdine ramène le gain à zéro mais mémorise la valeur du curseur.

**Le minuteur** enregistre l'instant où la session doit se terminer et recalcule le temps restant quatre fois par seconde. Les navigateurs peuvent ralentir `setInterval` dans les onglets en arrière-plan, mais comme l'affichage découle de l'horloge et non de ticks comptés, une session de 25 minutes se termine au bout de 25 minutes. À zéro, trois sons sinusoïdaux (un arpège de la majeur : 880, 1109 et 1319 Hz) jouent un carillon doux.

Le bouton Share utilise le menu de partage natif de l'appareil s'il existe, sinon il copie le lien de la page. Rien d'autre ne quitte la page : ni réglages ni utilisation ne sont enregistrés.

## Cas d'usage

- **Blocs de travail profond.** Lancez Deep Work, réglez 50 minutes et fermez tout le reste : le grondement régulier masque les conversations du bureau et le bruit de la rue.
- **Réviser avec la méthode Pomodoro.** Alternez sessions de 25 minutes et pauses de 5, avec une pause plus longue après quatre cycles.
- **Open spaces et colocations.** Un bruit rose ou brun à faible volume au casque couvre la parole intelligible, le son le plus gênant pour la plupart des gens.
- **Écrire et lire.** Un mélange léger Coffee Shop + Fireplace crée une ambiance de café sans paroles de chansons qui détournent l'attention.
- **Décompresser.** Pluie et bruit brun forment un fond apaisant pour lire avant de dormir ; le minuteur aide à lâcher le téléphone.
- **Timeboxing des tâches et réunions.** Réglez 10 ou 15 minutes pour la tâche que vous repoussez sans cesse : le carillon vous dit quand arrêter.
