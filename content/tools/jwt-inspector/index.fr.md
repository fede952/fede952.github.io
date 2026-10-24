---
title: "Décoder un JWT et Vérifier sa Signature"
description: "Décodez n'importe quel JSON Web Token, lisez ses claims et son expiration, et vérifiez une signature HS256, RS256, PS256 ou ES256 dans votre navigateur."
intro: "Collez un **JSON Web Token** pour voir son en-tête et son payload, lire `exp`, `nbf` et `iat` en heure lisible et vérifier la signature avec un secret ou une clé publique. Le décodage et la vérification se font dans votre navigateur : le token n'est jamais envoyé."
date: 2026-07-05
lastmod: 2026-10-24
reviewed: false
keywords: ["décoder jwt", "jwt decoder", "vérifier signature jwt", "jwt en ligne", "valider token jwt", "jwt rs256", "expiration jwt", "jwt debugger"]
tags: ["sécurité", "outils-développeur", "jwt", "outil"]
app_category: "DeveloperApplication"
tool_file: "/tools/jwt-inspector/"
tool_title: "TokenLens : décodeur JWT et vérificateur de signature"
tool_height: 1100
tool_sandbox: "allow-scripts allow-same-origin"
tool_allow: "clipboard-read; clipboard-write"
howto:
  - "Collez un token dans le champ ou cliquez sur **Paste** pour le lire depuis le presse-papiers. **Load sample** charge un token HS256 d'exemple."
  - "Le token est découpé en trois parties colorées et décodé aussitôt : l'en-tête et le payload s'affichent en JSON coloré."
  - "Regardez les pastilles d'état : algorithme, `typ`, `kid` et si le token est expiré ou pas encore valide. Le tableau des claims traduit `exp`, `nbf` et `iat` en dates locales."
  - "Pour vérifier, collez le **secret HMAC** pour HS256/384/512 (cochez *Secret is Base64URL-encoded* le cas échéant), ou la **clé publique** du signataire en PEM ou JWK pour les algorithmes RS, PS et ES."
  - "Cliquez sur **Verify signature**. Vert : la signature correspond à cette clé et le token n'a pas été modifié. Rouge : mauvaise clé ou token altéré."
faq:
  - q: "Puis-je coller ici un JWT de production sans risque ?"
    a: "L'outil fonctionne entièrement dans votre navigateur et n'envoie le token dans aucune requête réseau : rien n'est enregistré de notre côté. Mais un access token valide reste un mot de passe à durée limitée : quiconque le voit peut l'utiliser jusqu'à son expiration. Préférez des tokens expirés ou de test, et jamais dans un outil que vous ne pouvez pas inspecter."
  - q: "Quelle différence entre décoder et vérifier un JWT ?"
    a: "Décoder consiste seulement à inverser l'encodage Base64URL de l'en-tête et du payload, ce que tout le monde peut faire : un JWT est signé, pas chiffré. Vérifier consiste à recalculer la signature de `header.payload` avec la clé et à la comparer au troisième segment. Seule la vérification prouve que le token a été émis par le détenteur de la clé et n'a pas été modifié."
  - q: "Quels algorithmes peut-il vérifier ?"
    a: "HS256, HS384 et HS512 (HMAC avec secret partagé) ; RS256, RS384 et RS512 (RSA PKCS#1 v1.5) ; PS256, PS384 et PS512 (RSA-PSS) ; ES256, ES384 et ES512 (ECDSA sur P-256, P-384 et P-521). Les tokens en `alg: none` ou avec d'autres algorithmes sont décodés mais pas vérifiés."
  - q: "Où trouver la clé publique d'un token RS256 ?"
    a: "La plupart des fournisseurs d'identité publient leurs clés sous forme de JWKS à une URL du type `https://issuer/.well-known/jwks.json`. Trouvez l'entrée dont le `kid` correspond à l'en-tête du token et collez cet objet JWK. Une clé publique PEM (`-----BEGIN PUBLIC KEY-----`) fonctionne aussi."
  - q: "Pourquoi un token en \"alg\": \"none\" ne se vérifie-t-il pas ?"
    a: "Parce qu'il n'y a rien à vérifier : le token se déclare non signé. Accepter de tels tokens est une vulnérabilité classique ; le serveur doit décider lui-même des algorithmes acceptés au lieu de faire confiance à l'en-tête. L'inspecteur affiche l'algorithme bien en vue pour que cela saute aux yeux."
  - q: "La signature est valide mais l'API refuse le token. Pourquoi ?"
    a: "Une signature valide n'est qu'un contrôle parmi d'autres. Les serveurs vérifient aussi `exp`, `nbf`, l'émetteur (`iss`), l'audience (`aud`) et souvent les scopes. Regardez les pastilles d'état et le tableau des claims : un token expiré ou une mauvaise audience sont les causes les plus fréquentes."
  - q: "L'outil enregistre-t-il le secret ou la clé collés ?"
    a: "Non. Les clés sont importées avec `crypto.subtle.importKey` en mode non exportable, utilisées une fois pour la vérification puis abandonnées avec la page. Rien n'est écrit dans le stockage du navigateur."
---

## Comment ça marche

### Décodage

Un JWT est formé de trois segments Base64URL reliés par des points : `header.payload.signature`. L'inspecteur découpe la chaîne, vérifie qu'il y a exactement trois segments, convertit le Base64URL en Base64 standard (`-` devient `+`, `_` devient `/`, le padding `=` est rétabli), décode les octets en UTF-8 et lit l'en-tête et le payload avec `JSON.parse`. Une saisie mal formée produit un message d'erreur précis plutôt qu'un écran vide.

Les claims enregistrés du payload sont expliqués dans un tableau. Les claims temporels `exp` (expiration), `nbf` (pas avant) et `iat` (émis le) sont des valeurs **NumericDate**, des secondes depuis le 1er janvier 1970 UTC : ils sont convertis dans votre heure locale et en description relative comme « in 23 min » ou « 3 days ago ». La barre d'état signale un token expiré, un token pas encore valide et un token sans `exp`.

### Vérification

La vérification utilise la **Web Crypto API** intégrée au navigateur (`crypto.subtle`), pas une bibliothèque cryptographique JavaScript :

- L'entrée signée est la chaîne ASCII `header.payload`, telle qu'elle figure dans le token. Elle n'est pas réencodée : c'est pourquoi un token modifié à la main échoue.
- **HS256/384/512** : le secret est importé comme clé HMAC brute avec SHA-256, SHA-384 ou SHA-512, et `crypto.subtle.verify('HMAC', …)` contrôle le MAC.
- **RS256/384/512** : la clé publique est importée en `RSASSA-PKCS1-v1_5` avec le hachage correspondant.
- **PS256/384/512** : importée en `RSA-PSS` et vérifiée avec un sel de la longueur du hachage (32, 48 ou 64 octets), comme l'exige la RFC 7518.
- **ES256/384/512** : importée en `ECDSA` sur P-256, P-384 ou P-521. Les signatures ECDSA des JWS sont la concaténation brute `r‖s`, le format qu'attend Web Crypto : aucune conversion DER n'est nécessaire.

Les clés publiques peuvent être fournies en **PEM/SPKI** (le Base64 entre les lignes `BEGIN/END PUBLIC KEY` est décodé en DER) ou sous forme d'objet **JWK** en JSON. Les clés importées ne sont pas exportables et n'existent que le temps de la vérification.

### Un piège fréquent

Les secrets HMAC sont souvent configurés sous forme de chaînes Base64. Si votre backend décode le secret avant de signer, cochez *Secret is Base64URL-encoded* ; sinon la même chaîne visible donne une autre clé et la signature ne correspond pas.

## Cas d'usage

- **Déboguer l'authentification.** Comprenez pourquoi une requête renvoie 401 : `exp` dépassé, `aud` erroné, scope manquant ou token signé par une autre clé.
- **Vérifier une intégration avec un fournisseur d'identité.** Décodez l'ID token d'une connexion OAuth/OIDC et vérifiez-le avec le JWKS du fournisseur avant d'écrire le moindre code backend.
- **Revues de sécurité et pentests.** Repérez les tokens en `alg: none`, les durées de vie excessives, les données sensibles dans le payload ou un `kid` qui pointe là où il ne devrait pas.
- **Rotation de clés.** Confirmez que les tokens émis après une rotation se vérifient avec la nouvelle clé publique, et les anciens avec la précédente.
- **Pédagogie.** Montrez comment un token est construit et pourquoi le Base64URL est un encodage, pas un chiffrement.
