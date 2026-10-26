---
title: "Message chiffré avec mot de passe par lien"
description: "Chiffrez un message dans le navigateur avec AES-256 et une phrase secrète, puis partagez-le par lien. Le texte n'est jamais envoyé : il vit dans le lien."
intro: "Écrivez un message, choisissez une phrase secrète et obtenez un **lien** qui contient le message **chiffré avec AES-256-GCM**. Envoyez le lien et la phrase **par des canaux différents** ; le destinataire ouvre le lien et le déchiffre dans son navigateur. Rien n'est envoyé ni stocké : le texte chiffré voyage dans le lien lui-même, dans la partie après `#` que les navigateurs n'envoient jamais à un serveur."
date: 2026-10-26
lastmod: 2026-10-26
reviewed: false
keywords: ["lien message chiffré", "envoyer un message chiffré", "chiffrer un texte en ligne", "message protégé par mot de passe", "partager un mot de passe en sécurité", "envoyer une note secrète", "crypter un message avec mot de passe", "lien message privé"]
tags: ["security", "privacy", "encryption", "tool"]
app_category: "SecurityApplication"
tool_file: "/tools/encrypted-message/"
tool_title: "Lien de message chiffré"
tool_height: 900
tool_sandbox: "allow-scripts allow-same-origin"
tool_allow: "clipboard-write"
howto:
  - "Écrivez le **message** : un mot de passe Wi-Fi, un code de porte, une courte note privée."
  - "Saisissez une **phrase secrète** d'au moins 8 caractères, ou appuyez sur **Générer** pour en obtenir une aléatoire."
  - "Appuyez sur **Créer le lien chiffré** puis **Copier le lien**."
  - "Envoyez le lien par un canal (par exemple un e-mail) et la **phrase secrète par un autre** (un appel, une autre messagerie). Jamais les deux dans le même message."
  - "Le destinataire ouvre le lien, saisit la phrase et lit le message dans son propre navigateur."
faq:
  - q: "Mon message est-il envoyé quelque part ?"
    a: "Non. Le chiffrement se fait dans votre navigateur avec la Web Crypto API. Le message chiffré est placé dans le lien après le signe #, et les navigateurs n'envoient pas cette partie au serveur quand le lien est ouvert. Ce site ne reçoit jamais le message, la phrase secrète ni le fragment du lien : rien n'est stocké qui pourrait fuiter ou être supprimé."
  - q: "Le lien s'autodétruit-il après lecture ?"
    a: "Non, et aucun outil sans serveur ne peut le promettre. Le lien est le message chiffré : il fonctionne tant que quelqu'un en garde une copie, dans une boîte mail, un historique de discussion ou une sauvegarde. Traitez-le comme le secret lui-même : toute personne qui a le lien et la phrase peut le lire. S'il vous faut un message qui disparaît, utilisez un service qui le stocke sur un serveur et le supprime après lecture, en acceptant de faire confiance à ce serveur."
  - q: "Le chiffrement est-il solide ?"
    a: "Le message est chiffré avec AES-256 en mode GCM, qui détecte aussi toute modification du lien. La clé est dérivée de votre phrase avec PBKDF2-HMAC-SHA-256 et 600 000 itérations, avec un sel et un IV aléatoires pour chaque message. Le point faible est la phrase : une phrase courte ou devinable peut être cassée par force brute par quiconque a le lien, alors utilisez-en une longue ou le bouton Générer."
  - q: "Et si la phrase est fausse ou le lien coupé ?"
    a: "Le déchiffrement échoue avec un message clair. Le chiffrement authentifié ne distingue pas une phrase fausse d'un lien modifié : vérifiez les deux. Certaines applications coupent les liens très longs : l'outil vous prévient au-delà d'environ 2 000 caractères."
  - q: "Pourquoi envoyer la phrase séparément ?"
    a: "Parce que le lien seul est inutile sans elle. S'ils voyagent ensemble dans le même e-mail ou la même discussion, quiconque peut lire cette conversation, maintenant ou plus tard, par exemple après le piratage d'un compte, peut aussi lire le message."
  - q: "Puis-je voir ce que fait l'outil ?"
    a: "Oui. Le code s'exécute dans votre navigateur et se lit avec les outils de développement. Dans l'onglet Réseau, vous pouvez aussi vérifier que créer et ouvrir un lien n'envoie aucune requête contenant votre message."
---

## Comment ça marche

### Le chiffrement dans votre navigateur

Quand vous appuyez sur **Créer le lien chiffré**, la page génère un sel aléatoire de 16 octets et un IV aléatoire de 12 octets, dérive de votre phrase une clé de 256 bits avec **PBKDF2-HMAC-SHA-256** (600 000 itérations) et chiffre le message avec **AES-256-GCM**. Le sel, l'IV et le texte chiffré avec son étiquette d'authentification sont assemblés, encodés en Base64url et placés après `#v1.` dans le lien.

### Pourquoi le message n'atteint jamais un serveur

La partie d'une URL après `#` est le **fragment**. Les navigateurs la gardent sur l'appareil : elle n'est pas envoyée dans la requête de la page et n'apparaît pas dans l'en-tête `Referer`. Le lien ouvre une page minimale de ce site, sans publicité ni statistiques, qui lit le fragment, le retire de la barre d'adresse et demande la phrase secrète. Le déchiffrement a lieu sur l'appareil du destinataire.

### Ce contre quoi il ne protège pas

- **Une personne qui a le lien et la phrase** — c'est ainsi que le destinataire le lit, et ainsi que n'importe qui d'autre pourrait le lire.
- **Une phrase faible** — qui a le lien peut essayer des phrases hors ligne aussi vite que son matériel le permet ; les 600 000 itérations rendent chaque essai lent, pas impossible.
- **Un appareil compromis** — un logiciel malveillant chez l'expéditeur ou le destinataire peut lire le message avant le chiffrement ou après le déchiffrement.
- **Les copies du lien** — boîtes mail, historiques de discussion et sauvegardes le conservent. Impossible de le révoquer.

## Cas d'usage

- **Partager un mot de passe ou la clé Wi-Fi** avec un collègue ou un invité sans le laisser lisible dans l'historique de discussion.
- **Envoyer un code de porte ou le code d'une alarme** à un livreur ou à la personne qui garde la maison.
- **Transmettre un code de récupération ou une clé d'API** à un collègue par e-mail, avec la phrase donnée par téléphone.
- **Laisser une note privée** dans un lieu public — un ticket, un forum, un document partagé — que seules les personnes ayant la phrase peuvent lire.
- **Avant d'envoyer**, vérifiez à quel point votre phrase secrète est difficile à deviner avec [PassFort](../pass-fort/).
