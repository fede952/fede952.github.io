---
title: "Analyseur d'en-têtes de sécurité et CSP"
description: "Collez des en-têtes de réponse HTTP ou une Content-Security-Policy pour repérer en-têtes absents, règles CSP faibles et cookies non sûrs, avec le correctif."
intro: "Collez les **en-têtes de réponse** d'une page — issus de `curl -sI` ou des DevTools du navigateur — ou une **Content-Security-Policy** seule. L'analyseur vérifie **HSTS**, **CSP**, **X-Content-Type-Options**, la protection contre l'intégration en cadre, **Referrer-Policy**, **Permissions-Policy**, **COOP**, **CORS** et chaque **Set-Cookie**, explique chaque problème et indique le correctif. Il n'effectue **aucune requête réseau** : il lit seulement ce que vous collez, et fonctionne donc aussi pour des sites de préproduction ou d'intranet."
date: 2026-10-25
lastmod: 2026-10-25
reviewed: false
keywords: ["vérifier en-têtes de sécurité", "csp evaluator", "vérifier content security policy", "en-têtes de sécurité http", "analyseur csp", "vérifier hsts", "analyser en-têtes de réponse", "x-frame-options"]
tags: ["sécurité", "csp", "http", "tool"]
app_category: "SecurityApplication"
tool_file: "/tools/security-headers/"
tool_title: "Analyseur d'en-têtes de sécurité et de CSP"
tool_height: 1000
tool_sandbox: "allow-scripts allow-same-origin"
tool_allow: "clipboard-write"
howto:
  - "Copiez les en-têtes de réponse de la page à vérifier : lancez `curl -sI https://example.com` dans un terminal, ou ouvrez DevTools → **Réseau**, rechargez, sélectionnez la requête de la page et copiez ses **En-têtes de réponse**."
  - "Collez-les dans **En-têtes de réponse ou CSP**. Vous pouvez aussi coller une politique seule (`default-src 'self'; …`) ou une balise `<meta http-equiv=\"Content-Security-Policy\">`."
  - "Le résultat s'affiche dès le collage : une note, puis tous les constats triés d'**Élevé** à **OK**, chacun avec l'en-tête concerné et ce qu'il faut changer."
  - "Sous **Content-Security-Policy**, chaque directive est listée avec ses sources ; les sources risquées sont surlignées en rouge ou en orange, les sûres en vert."
  - "Cliquez sur **Copier le rapport** pour coller les constats dans un ticket ou une pull request. Essayez **Exemple faible** et **Exemple solide** pour voir la différence."
faq:
  - q: "L'outil se connecte-t-il à mon site ?"
    a: "Non. Il ne télécharge aucune URL : il analyse seulement le texte collé, dans votre navigateur. Votre serveur n'apparaît donc pas dans les journaux d'un tiers, et vous pouvez vérifier des sites non publics comme une préproduction, un intranet ou localhost."
  - q: "Pourquoi coller les en-têtes plutôt que saisir une URL ?"
    a: "Les règles CORS du navigateur empêchent une page web de lire une autre URL, sauf si un serveur le fait pour vous — et ce serveur verrait chaque site testé. Coller la sortie de `curl -sI` est tout aussi rapide et tout reste local."
  - q: "Qu'est-ce qui rend une Content-Security-Policy faible ?"
    a: "Les problèmes courants sont `'unsafe-inline'` dans script-src (exécute les scripts en ligne injectés), les sources de schéma comme `https:` ou `data:` et le joker `*` (scripts de presque partout), des CDN autorisés hébergeant des points JSONP ou l'ancien AngularJS, et l'absence d'object-src ou de base-uri. Une étude de Google a montré que la plupart des politiques fondées sur des listes d'hôtes sont contournables ; les nonces avec 'strict-dynamic' évitent cela."
  - q: "Qu'est-ce qu'une CSP stricte ?"
    a: "Une politique qui autorise les scripts par un nonce aléatoire (ou un hash) plutôt que par hôte, avec `'strict-dynamic'` pour que les scripts de confiance puissent en charger d'autres. C'est l'approche recommandée par Google et l'OWASP contre les XSS. L'exemple de « Comment ça marche » est un bon point de départ : déployez-le d'abord en Content-Security-Policy-Report-Only et corrigez ce qu'il signale."
  - q: "Comment la note est-elle calculée ?"
    a: "On part de 100 et on retire 20 points par constat élevé, 10 par moyen et 4 par faible ; les informations et les contrôles réussis ne coûtent rien. A+ exige l'absence de constat élevé ou moyen. La note est un résumé rapide, pas une certification : lisez les constats, car leur impact dépend de votre site."
  - q: "Ai-je encore besoin de X-Frame-Options et X-XSS-Protection ?"
    a: "Dans les navigateurs actuels, frame-ancestors de la CSP remplace X-Frame-Options, mais envoyer les deux est sans risque et couvre les anciens ; l'outil accepte donc l'un ou l'autre. X-XSS-Protection est obsolète : les navigateurs ont retiré le filtre qu'il pilotait, l'outil conseille donc de le supprimer ou d'envoyer 0."
  - q: "Quels attributs de cookies sont vérifiés ?"
    a: "Secure (envoyé uniquement en HTTPS), HttpOnly (caché à JavaScript), SameSite (limite l'envoi intersites, une défense contre le CSRF) et les règles des préfixes __Host- et __Secure-. Un cookie avec SameSite=None mais sans Secure est refusé par les navigateurs et signalé comme élevé."
---

## Comment ça marche

### Coller, découper, vérifier

Le texte collé est découpé en lignes d'en-têtes. Les lignes d'état comme `HTTP/2 200`, les pseudo-en-têtes HTTP/2 et les lignes repliées sont gérés ; si vous collez une chaîne de redirections, seule la dernière réponse est analysée. Les en-têtes répétés comme `Set-Cookie` sont vérifiés un par un. Si le texte commence par une directive CSP, ou est une balise `<meta>` CSP, seule la politique est analysée.

Chaque en-tête est ensuite comparé au comportement actuel des navigateurs et aux recommandations de l'OWASP, de MDN et de la spécification CSP. Chaque constat a une gravité, l'en-tête concerné et un correctif concret.

### Les contrôles de la CSP

La politique est découpée en directives et en sources. L'analyseur détermine la directive qui régit réellement les scripts (`script-src`, ou `default-src` à défaut) et les plugins (`object-src` hérite de `default-src` ; `base-uri` et `form-action` n'héritent de rien). Il signale `'unsafe-inline'` et `'unsafe-eval'`, les jokers, les sources de schéma, les hôtes en HTTP, les hôtes autorisés connus pour servir du JSONP ou des versions arbitraires de bibliothèques, les nonces courts, `'strict-dynamic'` sans nonce, et les erreurs de syntaxe que les navigateurs ignorent sans rien dire : mots-clés sans apostrophes (`self` au lieu de `'self'`), points-virgules manquants, directives dupliquées, inconnues ou obsolètes.

### Une politique stricte pour démarrer

```text
Content-Security-Policy:
  script-src 'nonce-{RANDOM}' 'strict-dynamic';
  object-src 'none';
  base-uri 'none';
  form-action 'self';
  frame-ancestors 'self'
```

Générez un nouveau nonce aléatoire (au moins 128 bits) pour chaque réponse et ajoutez `nonce="{RANDOM}"` à chaque balise `<script>`. Envoyez-la d'abord en `Content-Security-Policy-Report-Only`, corrigez ce qui casse, puis appliquez-la.

## Cas d'usage

- **Avant une mise en ligne.** Vérifiez les en-têtes d'un site de préproduction, inaccessible aux scanners en ligne.
- **Pull requests et audits.** Collez les en-têtes avant et après une modification et copiez le rapport dans la revue.
- **Apprendre la CSP.** Comprenez, directive par directive, pourquoi chaque source est ou n'est pas un risque.
- **Notes de pentest et de bug bounty.** Transformez une réponse capturée en liste de constats sur les en-têtes, avec correctifs.
- **Revue des cookies.** Vérifiez que les cookies de session restent Secure, HttpOnly et SameSite après une mise à jour du framework.
