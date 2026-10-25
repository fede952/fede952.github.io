---
title: "Générateur de Mot de Passe Sécurisé"
description: "Générez des mots de passe aléatoires robustes jusqu'à 64 caractères avec le générateur crypto du navigateur. Entropie en direct, copie en un clic."
intro: "Un **générateur de mot de passe sécurisé** en un clic : choisissez la longueur et les jeux de caractères, et obtenez un mot de passe aléatoire tiré du générateur cryptographique de votre navigateur, avec sa robustesse en bits."
date: 2026-02-03
lastmod: 2026-10-24
reviewed: false
keywords: ["générateur de mot de passe", "générateur mot de passe sécurisé", "mot de passe aléatoire", "créer un mot de passe fort", "générer mot de passe en ligne", "mot de passe 16 caractères", "générateur de mdp"]
tags: ["sécurité", "mots de passe", "outil"]
app_category: "SecurityApplication"
tool_partial: "password-generator"
howto:
  - "Faites glisser le curseur **Longueur** (8 à 64 caractères). Un nouveau mot de passe est généré à chaque déplacement."
  - "Décochez les jeux de caractères que le site n'accepte pas : majuscules **A–Z**, minuscules **a–z**, chiffres **0–9** ou symboles **!@#**."
  - "Regardez la ligne sous le mot de passe : elle indique l'entropie en bits et un niveau (Faible, Correct, Fort)."
  - "Cliquez sur **Générer un mot de passe** pour en obtenir un autre ; le bouton de copie à côté du champ le place dans le presse-papiers."
  - "Collez-le dans votre gestionnaire de mots de passe *avant* de fermer la page : le générateur ne garde aucun historique."
faq:
  - q: "Ce générateur de mots de passe est-il vraiment aléatoire ?"
    a: "Oui. Chaque caractère est choisi avec `crypto.getRandomValues()`, le générateur de nombres aléatoires cryptographiquement sûr du navigateur, avec un échantillonnage par rejet pour que chaque caractère du jeu ait exactement la même probabilité. Il n'utilise pas `Math.random()`, qui est prévisible et inadapté aux secrets."
  - q: "Le site peut-il voir les mots de passe que je génère ?"
    a: "Non. Le générateur tient en quelques lignes de JavaScript exécutées dans votre navigateur : aucune requête vers un serveur, aucun journal, aucun stockage. Coupez internet après le chargement de la page : il continue de fonctionner, c'est la preuve la plus simple."
  - q: "Quelle longueur choisir ?"
    a: "Avec les quatre jeux de caractères, 16 caractères donnent environ 104 bits d'entropie, bien au-delà de la portée de toute attaque par force brute. Passez à 20 ou plus pour les comptes très sensibles si le site l'accepte. Ne descendez sous 12 que si un vieux système vous y oblige."
  - q: "Pourquoi mon mot de passe ne contient-il aucun symbole alors qu'ils sont activés ?"
    a: "Chaque caractère est tiré indépendamment dans l'ensemble complet : le mot de passe n'est donc pas obligé de contenir un caractère de chaque type. Avec 16 caractères, c'est presque toujours le cas. Si un site le refuse faute de symbole ou de chiffre, générez-en un autre."
  - q: "Que signifient Faible, Correct et Fort ?"
    a: "Ce sont des tranches d'entropie : moins de 60 bits, Faible ; de 60 à 90 bits, Correct ; 90 bits et plus, Fort. Comme le mot de passe est tiré au hasard, ce chiffre est exact, contrairement aux jauges qui devinent l'entropie d'un mot de passe que vous avez inventé."
  - q: "Dois-je retenir ces mots de passe ?"
    a: "Non : enregistrez-les dans un gestionnaire et laissez-le les remplir. Pour le ou les deux mots de passe que vous devez vraiment mémoriser, comme le mot de passe maître, une longue phrase de passe aléatoire est plus pratique ; PassFort, sur ce site, peut en générer une."
---

## Comment ça marche

Le générateur constitue un ensemble à partir des jeux cochés : 26 majuscules, 26 minuscules, 10 chiffres et 29 symboles (`` !@#$%^&*()_+~`|}{[]:;?><,./-= ``), jusqu'à **91 caractères**. Pour chaque position, il demande à la Web Crypto API un nombre aléatoire de 32 bits via `crypto.getRandomValues()` et le convertit en caractère.

Cette conversion utilise l'**échantillonnage par rejet**. 2³² n'est pas un multiple de 91 : le simple `aléa % 91` rendrait quelques caractères très légèrement plus probables que les autres. À la place, toute valeur tombant dans la dernière tranche incomplète de la plage de 32 bits est écartée et retirée, et chaque caractère a exactement la même probabilité.

La ligne de robustesse n'est pas une supposition. Chaque caractère étant uniformément aléatoire, l'entropie vaut exactement **longueur × log₂(taille de l'ensemble)** :

| Réglages | Bits par caractère | 12 car. | 16 car. | 24 car. |
|---|---|---|---|---|
| Les quatre jeux (91) | 6,51 | 78 | 104 | 156 |
| Lettres + chiffres (62) | 5,95 | 71 | 95 | 143 |
| Minuscules + chiffres (36) | 5,17 | 62 | 83 | 124 |
| Chiffres seuls (10) | 3,32 | 40 | 53 | 80 |

Le niveau est **Faible** sous 60 bits, **Correct** de 60 à 90 bits et **Fort** à partir de 90 bits ; la barre est pleine à 128 bits. Modifier la longueur ou une case régénère aussitôt le mot de passe : ce que vous voyez correspond toujours aux réglages.

La copie passe par la Clipboard API asynchrone lorsque la page est servie en HTTPS, avec une solution de repli pour les anciens navigateurs. Le mot de passe n'existe que dans le champ : rechargez la page et il disparaît.

### Pourquoi l'entropie est la bonne mesure

Un attaquant qui connaît parfaitement ce générateur, ensemble et longueur compris, doit tout de même essayer en moyenne la moitié des 2^bits combinaisons. À 104 bits, cela fait environ 10³¹ essais : même à 10 milliards par seconde, il lui faudrait bien plus que l'âge de l'univers. Voilà pourquoi un mot de passe issu d'un bon générateur est fort *par construction*, alors qu'un mot de passe inventé n'est fort que si le dictionnaire de l'attaquant est petit.

## Cas d'usage

- **S'inscrire à un nouveau service.** Générez 16 caractères ou plus, enregistrez-les dans votre gestionnaire, terminé.
- **Changer de mot de passe après une fuite.** Remplacez un mot de passe réutilisé ou divulgué par un mot de passe unique et aléatoire, en commençant par votre messagerie, puisqu'elle permet de réinitialiser tous les autres.
- **Clés d'API, utilisateurs de base de données et comptes de service.** Décochez les symboles si une chaîne de connexion ou un script shell les gère mal, et augmentez la longueur pour rester au-dessus de 100 bits.
- **Réseaux Wi-Fi.** Générez une clé de 20 à 30 caractères pour votre box ; vous ne la tapez qu'une fois par appareil.
- **Identifiants temporaires.** Créez un mot de passe jetable pour un compte invité ou un document partagé, puis supprimez le compte une fois terminé.

Pour tester un mot de passe que vous utilisez déjà, et vérifier s'il figure dans une fuite de données connue, essayez [PassFort](/fr/tools/pass-fort/).
