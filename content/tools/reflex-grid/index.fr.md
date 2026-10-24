---
title: "Aim Trainer et Test de Réflexes en Ligne"
description: "Entraînez votre visée à la souris en sessions de 60 secondes : cliquez sur des cibles lumineuses, puis voyez touches, précision, temps de réaction et rang."
intro: "**ReflexGrid** est un aim trainer de 60 secondes : des cibles surgissent n'importe où sur la grille, vous les cliquez ou touchez le plus vite possible et obtenez à la fin vos touches, votre précision, votre temps moyen jusqu'à la cible et un rang de *Potato* à *Pro*."
date: 2026-02-03
lastmod: 2026-10-24
reviewed: false
keywords: ["aim trainer", "test de réflexes", "test temps de réaction", "entraîner sa visée", "test précision souris", "aim trainer en ligne", "entraînement fps", "test vitesse de clic"]
tags: ["jeux", "gaming", "réflexes", "outil"]
app_category: "GameApplication"
tool_file: "/tools/reflex-grid/"
tool_title: "ReflexGrid, entraîneur de visée"
tool_height: 760
tool_sandbox: "allow-scripts allow-same-origin"
howto:
  - "Cliquez sur **Start Training**. Le chronomètre de 60 secondes démarre et la première cible apparaît."
  - "Cliquez (ou touchez sur écran tactile) chaque cercle lumineux aussi vite et précisément que possible. Dès que vous touchez, une autre apparaît."
  - "Surveillez la barre du haut : temps restant, touches et précision en direct. Les clics manqués font baisser la précision."
  - "À la fin du temps, lisez les résultats : **Targets Hit**, **Accuracy**, **Avg Reaction** et **Total Clicks**, plus votre rang."
  - "Cliquez sur **Play Again** pour battre votre score. Échauffez-vous quelques manches avant de comparer vos résultats."
faq:
  - q: "Quel est un bon temps de réaction dans ce test ?"
    a: "La moyenne ici est le temps entre l'apparition d'une cible et votre touche : elle inclut le déplacement de la souris, pas seulement la réaction. Sous 300 ms (rang *Gamer*), c'est bien ; sous 200 ms (*Pro*), c'est excellent. Le temps de réaction visuelle simple d'un adulte tourne autour de 200–250 ms, les valeurs de ReflexGrid sont donc logiquement un peu plus élevées."
  - q: "Comment les rangs sont-ils calculés ?"
    a: "À partir du temps moyen jusqu'à la cible : moins de 200 ms *Pro*, moins de 300 ms *Gamer*, moins de 400 ms *Casual*, moins de 500 ms *Novice*, au-delà *Potato*. La précision est affichée à part ; pour progresser vraiment, gardez-la au-dessus d'environ 80 % tout en réduisant le temps."
  - q: "La sensibilité ou les DPI de la souris comptent-ils ?"
    a: "Oui, énormément. S'entraîner à viser n'a de sens qu'avec la sensibilité avec laquelle vous jouez : gardez vos DPI et réglages de pointeur. Désactiver « Améliorer la précision du pointeur » (l'accélération) sous Windows rend les mouvements plus réguliers et plus faciles à entraîner."
  - q: "Pourquoi certaines cibles sont-elles rouges ?"
    a: "Environ 40 % des cibles sont rouges au lieu de cyan, simplement pour varier et éviter que vous anticipiez. Elles comptent pareil."
  - q: "Peut-on jouer sur téléphone ?"
    a: "Oui. Le canvas écoute les événements tactiles autant que la souris : les touches à l'écran comptent comme des clics. Les temps tactiles ne sont pas comparables à ceux de la souris ; comparez-vous à vous-même sur le même appareil."
  - q: "Mes scores sont-ils enregistrés ou envoyés ?"
    a: "Non. Chaque session n'existe que dans la page ; rien n'est stocké ni envoyé. Notez votre meilleur résultat si vous voulez suivre vos progrès."
---

## Comment ça marche

Le jeu est dessiné sur un `<canvas>` HTML adapté à la densité de pixels de votre écran, avec une grille de fond animée et une barre d'affichage en haut.

**Cibles.** Chaque cible reçoit un rayon aléatoire entre 20 et 35 pixels et une position aléatoire, éloignée des bords et de la barre. Elle pulse de ±12 %, de sorte qu'elle n'est jamais parfaitement immobile. Le moment de son apparition est enregistré avec `performance.now()`, l'horloge haute résolution du navigateur.

**Touches et ratés.** À chaque `mousedown` ou `touchstart`, la distance entre le pointeur et le centre de la cible est calculée avec Pythagore. Tout ce qui se trouve dans 1,3 fois le rayon compte comme une touche, une petite marge pour le halo et la pulsation. Une touche enregistre le temps de réaction (maintenant − apparition), joue un bref son carré ascendant généré par la Web Audio API, projette des particules et fait apparaître aussitôt la cible suivante. Un raté joue un son en dents de scie descendant et augmente seulement le nombre de clics.

**Score.** À la fin des 60 secondes :

- **Targets Hit** est le nombre de clics réussis ;
- **Accuracy** vaut touches ÷ clics totaux ;
- **Avg Reaction** est la moyenne de tous les temps de réaction enregistrés, en millisecondes ;
- le **rang** dépend de cette moyenne.

| Temps moyen jusqu'à la cible | Rang |
|---|---|
| moins de 200 ms | Pro |
| 200–299 ms | Gamer |
| 300–399 ms | Casual |
| 400–499 ms | Novice |
| 500 ms et plus | Potato |

Comme chaque cible apparaît à l'instant où la précédente est touchée, le test mesure la vitesse de *flick* : voir une nouvelle cible, s'y déplacer et cliquer. C'est plus proche de ce qu'exigent les FPS qu'un test « attendez que l'écran devienne vert ».

## Cas d'usage

- **S'échauffer avant un FPS** comme Valorant, CS2, Apex Legends ou Overwatch : deux ou trois manches synchronisent la main et les yeux.
- **Tester une nouvelle souris ou sensibilité.** Jouez quelques manches avec chaque réglage et comparez précision et temps jusqu'à la cible.
- **Suivre ses progrès.** Notez moyenne et précision chaque jour ; un entraînement régulier se traduit par des temps plus bas à précision égale.
- **Une pause rapide.** Une minute de clics concentrés est une bonne coupure entre deux longues séances de travail.
- **Ergonomie.** Une chute soudaine de précision peut être un signe de fatigue : faites une pause.
