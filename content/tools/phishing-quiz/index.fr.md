---
title: "Quiz hameçonnage : repérez-vous le piège ?"
description: "Test de phishing gratuit : 10 e-mails, SMS, pages de connexion, QR codes et liens réalistes. Repérez l'arnaque, voyez les signaux et partagez votre score."
intro: "Dix scénarios réalistes — **e-mails, SMS, pages de connexion, QR codes et liens** — tirés au hasard parmi 32. Pour chacun, décidez : **hameçonnage ou légitime ?** Après chaque réponse, les signaux d'alerte sont surlignés directement sur la maquette, avec une explication d'une ligne. Toutes les marques et tous les domaines sont fictifs, et rien de ce que vous faites ne quitte votre navigateur."
date: 2026-10-26
lastmod: 2026-10-26
reviewed: false
keywords: ["quiz phishing", "test phishing", "quiz hameçonnage", "reconnaître le phishing", "simulation de phishing", "comment reconnaître un mail frauduleux", "test smishing", "sensibilisation cybersécurité"]
tags: ["sécurité", "phishing", "sensibilisation", "tool"]
app_category: "EducationalApplication"
tool_file: "/tools/phishing-quiz/"
tool_title: "Quiz hameçonnage"
tool_height: 980
tool_sandbox: "allow-scripts allow-same-origin allow-top-navigation-by-user-activation"
tool_allow: "clipboard-write; web-share"
share_scores: 10
share_card_title: "J'ai fait {score}/10 au quiz hameçonnage"
howto:
  - "Cliquez sur **Commencer le quiz**. Vous recevez 10 scénarios ; trois ou quatre sont légitimes, donc « tout est de l'hameçonnage » ne marche pas."
  - "Lisez la ligne de contexte, puis examinez la maquette comme l'original : l'adresse de l'expéditeur, où mène vraiment le lien (survolez ou mettez le focus sur le bouton), la barre d'adresse, le nom de la pièce jointe."
  - "Répondez **Hameçonnage** ou **Légitime**. Les signaux d'alerte (ou les indices d'un message authentique) sont numérotés sur la maquette et expliqués en dessous."
  - "À la fin, vous obtenez un score, un niveau et les thèmes à revoir, avec des liens vers des outils utiles pour chacun."
  - "Utilisez **Partager mon score** pour envoyer le résultat : le texte partagé ne contient que le score et un lien."
faq:
  - q: "Les entreprises du quiz sont-elles réelles ?"
    a: "Non. Toutes les marques, personnes, numéros et domaines sont inventés, et toutes les adresses web utilisent des domaines réservés à la documentation (.example, .test) ou la plage d'IP de documentation 192.0.2.x : rien dans le quiz ne renvoie à une organisation réelle."
  - q: "Mon score ou mes clics sont-ils envoyés quelque part ?"
    a: "Non. Le quiz fonctionne entièrement dans votre navigateur et ne fait aucune requête réseau. Rien n'est enregistré. Le partage est votre choix : le bouton transmet seulement le score et l'adresse du quiz au menu de partage du téléphone, ou les copie."
  - q: "Comment les questions sont-elles choisies ?"
    a: "Chaque partie tire au hasard 10 scénarios sur 32, dont trois ou quatre légitimes et au moins trois types différents (e-mail, SMS, page de connexion, QR code, lien). En rejouant, vous obtenez un autre mélange."
  - q: "Que sont le smishing et le quishing ?"
    a: "Le smishing est l'hameçonnage par SMS ou messagerie. Le quishing passe par un QR code : sur un autocollant, une affiche ou dans un e-mail. Un QR code cache l'adresse jusqu'au scan et vous fait passer sur votre téléphone, où vous ne pouvez pas survoler un lien avant de l'ouvrir."
  - q: "Que faire d'un vrai message d'hameçonnage ?"
    a: "Ne cliquez pas, ne répondez pas, n'ouvrez pas les pièces jointes. Signalez-le — au travail à votre équipe informatique ou sécurité, sinon avec l'option « Signaler l'hameçonnage » de votre messagerie — puis supprimez-le. Si vous avez déjà saisi un mot de passe, changez-le tout de suite sur le vrai site et activez l'authentification à deux facteurs."
  - q: "Puis-je l'utiliser pour une formation de sensibilisation ?"
    a: "Oui, c'est gratuit et sans inscription. Voir « L'utiliser pour former votre équipe » ci-dessous pour une façon simple de l'animer en réunion."
---

## Comment ça marche

Chaque scénario est une maquette construite avec de vrais éléments de page, pas une image : elle se lit avec un lecteur d'écran et se joue entièrement au clavier. Elle s'accompagne d'une ligne de contexte (« Vous attendez une livraison… »), car le caractère suspect d'un message dépend souvent de ce que vous étiez en train de faire.

Les scénarios couvrent les ressorts de la plupart des hameçonnages :

- **Expéditeur et domaines sosies** — `velorabank-alerts.test` au lieu de `velorabank.example`, un chiffre 1 à la place d'un l.
- **Où mène vraiment un lien** — le texte visible dit une chose, la destination une autre ; un nom connu seulement comme sous-domaine du domaine de quelqu'un d'autre ; l'astuce du `@`.
- **La pression** — délais, menaces de suspension, secret, « je ne peux pas parler ».
- **Des demandes qu'aucun vrai service ne fait** — code PIN de carte, cartes cadeaux, frais pour débloquer un colis.
- **Pièces jointes et QR codes** — types de fichiers déguisés, QR codes qui vous font passer sur votre téléphone.

Le lot contient aussi des messages légitimes, car la méfiance excessive a un coût : vraies alertes de sécurité, reçus, réinitialisations de mot de passe que vous avez demandées. Après votre réponse, les éléments qui tranchent sont numérotés sur la maquette.

La page de résultat vous attribue un niveau et liste les thèmes derrière vos erreurs, avec des liens vers des outils utiles : [Link Hazmat](../link-hazmat/) pour vérifier les liens suspects et l'analyseur d'en-têtes d'e-mail pour contrôler l'expéditeur.

## L'utiliser pour former votre équipe

Le quiz fonctionne bien comme séquence de 15 minutes en réunion d'équipe :

1. **Partagez votre écran** et ouvrez cette page. Lancez le quiz.
2. **Lisez chaque scénario à voix haute** et laissez 30 secondes à la salle. Faites voter, à main levée ou dans le chat, avant que quiconque clique.
3. **Répondez comme la majorité**, puis passez en revue ensemble les signaux numérotés. Demandez qui les avait repérés.
4. **Après la partie**, demandez à chacun de jouer une fois seul et de partager son score dans le chat. Le message partagé ne contient que le score et le lien.
5. **Terminez par votre propre circuit de signalement** : à qui le dire, comment, et ce qui se passe ensuite.

Chaque partie est différente : les mêmes personnes peuvent rejouer lors d'une prochaine séance. Rien n'est suivi : le quiz est un exercice d'apprentissage, pas une évaluation individuelle.

## Cas d'usage

- **Sensibilisation à la sécurité** pour les équipes, écoles et familles, sans compte ni collecte de données.
- **Intégration** : une introduction rapide et concrète aux messages que recevront les nouveaux arrivants.
- **Vérification personnelle** avant d'ouvrir ce message de la banque ou du transporteur que vous n'attendiez pas.
- **Enseignement** de la différence entre un message suspect et un message authentique, avec les maquettes comme support de discussion.
