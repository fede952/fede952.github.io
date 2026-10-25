---
title: "Vérifier SPF, DKIM et DMARC d'un domaine"
description: "Vérifiez les enregistrements SPF, DKIM et DMARC d'un domaine, comptez les requêtes SPF face à la limite de 10, contrôlez les clés DKIM et BIMI."
intro: "Saisissez un domaine pour noter son **authentification e-mail**. L'outil lit l'enregistrement **SPF** et compte ses requêtes DNS **à travers chaque include** face à la limite de 10, lit la **politique DMARC**, le pourcentage, les adresses de rapport et l'alignement, mesure la **taille des clés DKIM** et vérifie **MX** et **BIMI**. Chaque problème est accompagné d'un **exemple d'enregistrement** pour le corriger. Les requêtes DNS partent vers le résolveur DNS-over-HTTPS de Cloudflare, uniquement quand vous appuyez sur Vérifier."
date: 2026-10-26
lastmod: 2026-10-26
reviewed: false
keywords: ["vérifier spf", "vérifier dmarc", "vérifier dkim", "test spf dkim dmarc", "vérifier enregistrement spf", "exemple enregistrement dmarc", "spf trop de requêtes dns", "taille clé dkim", "politique dmarc reject", "enregistrement bimi"]
tags: ["security", "email", "dns", "tool"]
app_category: "SecurityApplication"
tool_file: "/tools/spf-dmarc-checker/"
tool_title: "Vérificateur SPF, DKIM et DMARC"
tool_height: 1150
tool_sandbox: "allow-scripts allow-same-origin"
tool_allow: "clipboard-write"
howto:
  - "Saisissez un **domaine** (ou collez une adresse e-mail : seule la partie après @ est utilisée)."
  - "Facultatif : saisissez vos **sélecteurs DKIM**, séparés par des virgules. Sans eux, l'outil essaie des noms de sélecteur courants."
  - "Appuyez sur **Vérifier**. C'est le seul moment où des requêtes DNS partent."
  - "Lisez la **note** et chaque section : SPF avec le compteur de requêtes et l'arbre des include, balises DMARC, clés DKIM, MX et BIMI."
  - "Sous **Corrections suggérées**, copiez les exemples d'enregistrements, remplacez les parties entre chevrons et vérifiez avec votre fournisseur de messagerie avant de les publier."
faq:
  - q: "Qu'est-ce qui est envoyé, et à qui ?"
    a: "Quand vous appuyez sur Vérifier, votre navigateur envoie des requêtes DNS pour le domaine (ses enregistrements TXT pour SPF, _dmarc, les sélecteurs DKIM et BIMI, et ses enregistrements MX) au résolveur public DNS-over-HTTPS de Cloudflare, cloudflare-dns.com. Comme toute requête web, cela révèle à Cloudflare votre adresse IP et le user-agent du navigateur. Rien n'est envoyé à ce site, et rien ne part avant que vous appuyiez sur le bouton."
  - q: "Pourquoi SPF est-il limité à 10 requêtes ?"
    a: "La norme SPF (RFC 7208) limite à 10 par vérification les mécanismes qui demandent une requête DNS — include, a, mx, ptr, exists et le modificateur redirect —, comptés à travers tous les include imbriqués. Les destinataires qui dépassent la limite s'arrêtent sur une erreur permanente : SPF échoue alors pour tout votre courrier, pas seulement pour les expéditeurs en trop. ip4, ip6 et all ne comptent pas."
  - q: "Pourquoi aucune clé DKIM n'est trouvée alors que mon courrier est signé ?"
    a: "Les clés DKIM se trouvent sous un nom de sélecteur choisi par votre fournisseur (selecteur._domainkey.votredomaine), et le DNS ne permet pas de les lister. L'outil n'essaie que quelques noms courants. Trouvez votre sélecteur dans la balise s= d'un en-tête DKIM-Signature (l'analyseur d'en-têtes d'e-mail de ce site l'affiche) et saisissez-le."
  - q: "p=none suffit-il ?"
    a: "C'est la bonne première étape : vous recevez des rapports sans toucher à la livraison. Mais cela n'empêche personne d'usurper votre domaine. Quand les rapports montrent que vos expéditeurs légitimes passent, passez à p=quarantine puis à p=reject."
  - q: "~all ou -all ?"
    a: "Les deux marquent les serveurs non listés comme non autorisés. Avec DMARC en quarantine ou reject, les destinataires suivent de toute façon le résultat DMARC : ~all est donc un choix courant et sûr ; -all est plus strict, et certains destinataires peuvent rejeter le message pour cette seule raison, avant d'évaluer DMARC."
  - q: "Les exemples d'enregistrements sont-ils prêts à coller ?"
    a: "Ce sont des points de départ construits à partir de vos enregistrements actuels. Les parties entre chevrons doivent être remplacées, et seuls vous ou votre fournisseur connaissez tous les services qui envoient pour votre domaine. Vérifiez avec votre fournisseur, puis relancez la vérification une fois le DNS mis à jour."
---

## Comment ça marche

### SPF : compter les requêtes comme les destinataires

L'outil récupère les enregistrements TXT du domaine et garde celui qui commence par `v=spf1`. Il le parcourt ensuite terme par terme. Chaque `include`, `a`, `mx`, `ptr`, `exists` et `redirect` ajoute une requête, et chaque `include` est récupéré et parcouru à son tour : les fournisseurs imbriqués comptent donc aussi. Le total est comparé à la limite de 10 de la RFC 7208. L'outil signale aussi les include vers des domaines sans SPF, plus de deux requêtes qui ne renvoient rien, les boucles d'include, le mécanisme déconseillé `ptr` et le qualificateur de `all`.

### DMARC : politique, couverture et rapports

L'enregistrement de `_dmarc.<domaine>` est analysé balise par balise. Un sous-domaine sans enregistrement propre hérite de celui du domaine principal et de sa politique `sp=`, comme le font les destinataires. La note dépend de la politique (`none`, `quarantine`, `reject`), de `pct`, de la présence de rapports agrégés (`rua`), et du fait que les adresses de rapport sur un autre domaine aient publié l'enregistrement d'autorisation nécessaire (RFC 7489, section 7.1).

### DKIM : taille de clé lue dans la clé publique

Pour chaque sélecteur trouvé, la valeur `p=` est décodée et la taille du module RSA est lue dans la clé. Les destinataires ne doivent pas accepter de clés de moins de 1024 bits (RFC 8301) ; la taille recommandée est de 2048 bits. Les clés vides sont signalées comme révoquées, et les clés Ed25519 sont reconnues.

### MX et BIMI

Les enregistrements MX indiquent où le domaine reçoit son courrier ; un « MX nul » (`0 .`) signifie qu'il n'en accepte aucun. BIMI (`default._bimi`) est facultatif et ne fonctionne qu'avec une politique DMARC appliquée à 100 %.

## Cas d'usage

- **Avant d'envoyer une lettre d'information** — assurez-vous que SPF, DKIM et DMARC passent pour arriver en boîte de réception.
- **Après l'ajout d'un service d'envoi** — vérifiez que le nouvel `include:` n'a pas fait dépasser les 10 requêtes SPF.
- **Sécuriser un domaine** — passez DMARC de `p=none` à `p=reject` en confiance, et protégez les domaines qui n'envoient jamais de courrier.
- **Audits de sécurité** — contrôlez la protection contre l'usurpation des domaines d'un fournisseur ou de votre organisation.
- **Examiner un e-mail suspect** — voyez ce que publie le domaine de l'expéditeur, puis lisez le message avec l'[analyseur d'en-têtes d'e-mail](../email-header-analyzer/).
