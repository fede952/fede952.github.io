---
title: "Tester un Mot de Passe & Générateur"
description: "Testez la robustesse d'un mot de passe (entropie en bits, temps pour le casser) et générez mots de passe et phrases de passe aléatoires, en local."
intro: "**PassFort** génère des mots de passe et des phrases de passe aléatoires avec le générateur cryptographique de votre navigateur, et évalue l'entropie et le temps d'attaque par force brute de n'importe quel mot de passe. Rien de ce que vous tapez ne quitte cette page."
date: 2026-02-03
lastmod: 2026-10-24
reviewed: false
keywords: ["tester mot de passe", "générateur de mot de passe", "vérifier robustesse mot de passe", "générateur phrase de passe", "entropie mot de passe", "combien de temps pour casser mon mot de passe", "mot de passe aléatoire", "mot de passe fort"]
tags: ["sécurité", "mots de passe", "vie privée", "outil"]
app_category: "SecurityApplication"
tool_file: "/tools/pass-fort/"
tool_title: "PassFort : générateur et testeur de mots de passe"
tool_height: 900
tool_sandbox: "allow-scripts allow-same-origin"
tool_allow: "clipboard-write"
howto:
  - "Ouvrez l'onglet **Generator**. Choisissez la longueur (8 à 128 caractères) et les jeux de caractères : majuscules, minuscules, chiffres, symboles."
  - "Pour un secret à taper et à retenir, cochez **Passphrase Mode** et choisissez de 3 à 8 mots. Pour un mot de passe maître, au moins 6."
  - "Cliquez sur **Generate Password** jusqu'à obtenir un résultat qui vous convient ; le bouton presse-papiers le copie. Collez-le directement dans votre gestionnaire de mots de passe."
  - "Pour vérifier un mot de passe que vous utilisez déjà, passez à l'onglet **Auditor** et tapez-le ou collez-le. Le bouton en forme d'œil l'affiche ou le masque."
  - "Lisez la jauge d'entropie, le temps de cassage estimé et la liste de contrôles : tout ce qui est rouge mérite d'être corrigé avant de réutiliser ce mot de passe."
faq:
  - q: "Est-il sûr de taper mon vrai mot de passe dans ce testeur ?"
    a: "Oui. L'auditeur est du JavaScript qui s'exécute dans cette page : il n'envoie jamais sur le réseau ce que vous tapez, et la valeur disparaît dès que vous videz le champ ou fermez l'onglet. Vous pouvez le vérifier dans les outils de développement du navigateur (onglet Réseau) pendant la saisie. Si vous préférez, testez un mot de passe qui *suit le même schéma* que le vrai."
  - q: "Combien de bits d'entropie faut-il pour un mot de passe solide ?"
    a: "Pour des comptes protégés par un hachage lent et salé, 60 à 70 bits d'entropie *aléatoire* résistent très longtemps à une attaque par force brute hors ligne. Pour le mot de passe maître d'un gestionnaire ou le chiffrement de disque, visez 80 à 100 bits. Un mot de passe aléatoire de 16 caractères utilisant les quatre jeux donne environ 103 bits ; une phrase de passe PassFort de 7 mots, environ 72 bits."
  - q: "Phrase de passe ou mot de passe aléatoire : lequel choisir ?"
    a: "Les deux sont solides si une machine choisit les mots ou les caractères au hasard. Les mots de passe aléatoires concentrent plus d'entropie par caractère et sont parfaits quand votre gestionnaire les saisit pour vous. Les phrases de passe sont plus faciles à taper et à retenir : c'est le meilleur choix pour les quelques mots de passe que vous saisissez à la main, à condition d'utiliser assez de mots."
  - q: "Pourquoi le testeur affiche-t-il « des siècles » pour un mot de passe que je sais faible ?"
    a: "L'estimation suppose que chaque caractère a été choisi au hasard. Un vrai attaquant commence par des dictionnaires, des listes de mots de passe divulgués et des règles comme « majuscule au début, année à la fin » : `Soleil2024!` tombe donc en quelques secondes même si son entropie brute semble correcte. PassFort ne repère que quelques motifs évidents (commencer par 123, abc, password, qwerty, 111 ou aaa) ; pour un mot de passe inventé par un humain, considérez le score comme une limite haute."
  - q: "Que signifie « 10 milliards d'essais par seconde » ?"
    a: "C'est la vitesse d'attaque retenue par l'estimation : à peu près un GPU moderne contre un hachage rapide et non salé comme MD5 ou NTLM. Contre bcrypt, scrypt ou Argon2, l'attaquant est des milliers de fois plus lent, donc les temps réels sont généralement plus longs. Contre un formulaire de connexion en ligne avec limitation des tentatives, bien plus longs encore."
  - q: "PassFort enregistre-t-il les mots de passe qu'il génère ?"
    a: "Non. Les mots de passe générés n'existent que dans la mémoire de la page jusqu'à ce que vous les copiiez. Il n'y a ni compte, ni stockage, ni serveur derrière l'outil. Enregistrez le mot de passe dans un gestionnaire : une fois l'onglet fermé, il est impossible de le récupérer."
  - q: "Quelle longueur pour un mot de passe en 2026 ?"
    a: "Si un gestionnaire le génère et le stocke, au moins 16 caractères aléatoires : cela ne vous coûte rien. Si vous devez le mémoriser, une phrase de passe de 6 mots aléatoires ou plus. La longueur l'emporte sur les règles de complexité : un long mot de passe aléatoire en minuscules seulement est plus fort qu'un court bourré de symboles."
---

## Comment ça marche

### Le générateur

Chaque caractère provient de `crypto.getRandomValues()`, le générateur de nombres aléatoires cryptographiquement sûr de la Web Crypto API, que le navigateur alimente avec la source d'entropie du système d'exploitation. `Math.random()` n'est jamais utilisé.

Pour transformer un nombre aléatoire de 32 bits en position dans le jeu de caractères, PassFort utilise l'**échantillonnage par rejet** : les valeurs qui tombent dans le dernier « bloc » incomplet de la plage de 32 bits sont écartées et retirées. Le simple `aléa % taille` rendrait les premiers caractères du jeu légèrement plus probables. Le biais est infime, mais rien ne justifie de l'accepter.

Les quatre jeux comptent 26 majuscules, 26 minuscules, 10 chiffres et 26 symboles (`!@#$%^&*()_+-=[]{}|;:,.<>?`), soit 88 caractères. Chaque caractère ajoute donc log₂(88) ≈ **6,46 bits** d'entropie :

| Longueur | Les quatre jeux | Minuscules seules |
|---|---|---|
| 12 | ≈ 77 bits | ≈ 56 bits |
| 16 | ≈ 103 bits | ≈ 75 bits |
| 20 (par défaut) | ≈ 129 bits | ≈ 94 bits |

Les caractères sont tirés indépendamment : un mot de passe court ne contient donc pas *forcément* chaque jeu coché. Régénérez-le si un site exige, par exemple, un chiffre.

### Le mode phrase de passe

Le mode phrase de passe choisit des mots dans une liste intégrée de **1 207 mots anglais** avec le même index aléatoire non biaisé, met une majuscule à chacun et les relie par des tirets (par exemple `Harbor-Canyon-Crisp-Velvet`). Chaque mot apporte log₂(1207) ≈ **10,24 bits** : 4 mots donnent environ 41 bits, 6 mots environ 61 bits et le maximum de 8 mots environ 82 bits.

C'est moins par mot qu'une liste Diceware complète de 7 776 mots (12,9 bits) ; c'est pourquoi cette page conseille au moins 6 mots pour tout ce qui compte. Les majuscules et les tirets sont fixes et n'ajoutent pas d'entropie.

### L'auditeur

L'auditeur estime la taille de « l'alphabet » dont est issu votre mot de passe : 26 s'il contient une minuscule, +26 pour les majuscules, +10 pour les chiffres et +33 pour tout autre caractère. L'entropie vaut alors `longueur × log₂(alphabet)`.

Le temps de cassage est le temps nécessaire pour essayer les 2^entropie combinaisons à **10¹⁰ essais par seconde**, affiché en unités parlantes jusqu'à « des siècles ». La jauge est pleine à 100 bits et passe du rouge à l'orange, au jaune puis au vert à 25, 50 et 75 bits. En dessous, huit contrôles : au moins 8 et 12 caractères, chaque classe de caractères, aucun motif initial courant, au moins 60 bits.

C'est le modèle classique de « force brute ». Il est exact pour des mots de passe aléatoires comme ceux du générateur, et **optimiste pour ceux qu'inventent les humains**, car il ne voit ni mots du dictionnaire, ni prénoms, ni dates.

## Cas d'usage

- **Nouveaux comptes.** Générez un mot de passe de 16 à 20 caractères et enregistrez-le dans votre gestionnaire. Vous n'aurez plus jamais besoin de le voir.
- **Les mots de passe à retenir.** Mot de passe maître du gestionnaire, session de l'ordinateur, chiffrement du disque : utilisez une phrase de passe de 6 à 8 mots que vous tapez sans erreur.
- **Revoir ses vieilles habitudes.** Collez un mot de passe utilisé depuis des années, regardez son score et remplacez les faibles, en commençant par la messagerie et la banque.
- **Clés Wi-Fi et secrets partagés.** Les phrases de passe WPA2/WPA3 acceptent jusqu'à 63 caractères : une longue phrase aléatoire ne coûte rien et empêche de casser hors ligne un handshake capturé.
- **Formation et politiques de sécurité.** Le tableau ci-dessus et la jauge en direct rendent l'entropie concrète quand vous expliquez à vos collègues pourquoi « 8 caractères avec un symbole » n'est plus une bonne règle.
