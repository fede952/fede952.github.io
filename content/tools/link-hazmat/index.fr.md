---
title: "Ce Lien est-il Sûr ? Détecteur de Phishing"
description: "Collez un lien suspect et voyez les ruses de phishing dans sa structure : IP, connexions cachées par @, domaines punycode, TLD à risque. Sans l'ouvrir."
intro: "**LinkHazmat** décortique une URL *sans la visiter* et signale les ruses structurelles des liens de phishing : hôtes en adresse IP, identifiants cachés par `@`, sosies de domaines en punycode, TLD à risque, noms de marques dans les sous-domaines et paramètres de redirection. Il vous donne ensuite des liens directs vers des scanners de réputation plus poussés."
date: 2026-02-14
lastmod: 2026-10-24
reviewed: false
keywords: ["ce lien est-il sûr", "vérifier un lien", "détecteur de phishing", "lien suspect", "scanner d'url", "comment savoir si un lien est sûr", "reconnaître un lien de phishing", "tester un lien"]
tags: ["sécurité", "phishing", "scanner-url", "outil"]
app_category: "SecurityApplication"
tool_partial: "link-hazmat"
howto:
  - "Copiez le lien suspect *sans l'ouvrir* : appui long ou clic droit, puis « Copier l'adresse du lien »."
  - "Collez-le dans le champ et cliquez sur **INITIATE SCAN** (ou Entrée). Si `http://` manque, il est ajouté automatiquement."
  - "Lisez le verdict : **LOW RISK**, **SUSPICIOUS** ou **HIGH RISK**, avec chaque ruse détectée listée sous *Tricks detected*."
  - "Vérifiez le protocole, le vrai domaine et l'extension (TLD) vers lesquels pointe réellement le lien : le vrai domaine est souvent très différent de ce que suggère le texte du lien."
  - "Pour un second avis, utilisez les boutons **VirusTotal**, **Google Transparency** ou **Urlscan.io**, qui ouvrent ces services avec le lien déjà renseigné."
faq:
  - q: "Comment savoir si un lien est sûr avant de cliquer ?"
    a: "Regardez le vrai domaine, la partie juste avant le premier `/` simple. Dans `https://paypal.com.secure-login.xyz/…`, le domaine est `secure-login.xyz`, pas PayPal. Méfiez-vous des adresses IP au lieu de noms, d'un `@` dans l'adresse, d'extensions inhabituelles, de nombreux tirets et de toute page qui demande de vous connecter après un e-mail ou un SMS."
  - q: "LinkHazmat visite-t-il le lien ?"
    a: "Non. L'URL est seulement analysée comme du texte avec le parseur `URL` du navigateur ; rien n'est téléchargé, une page malveillante ne peut donc ni se charger ni exécuter quoi que ce soit. Un tiers ne voit le lien que si vous cliquez sur l'un des boutons de scanners externes."
  - q: "Un lien LOW RISK peut-il quand même être dangereux ?"
    a: "Oui. C'est une analyse structurelle : elle repère les ruses qui font *paraître* un lien légitime, pas si le site derrière un domaine d'apparence normale est malveillant. Un domaine fraîchement enregistré avec une structure propre obtient un score bas. Dans le doute, utilisez les scanners de réputation ou ouvrez le site en tapant vous-même son adresse."
  - q: "Qu'est-ce qu'une attaque punycode ou homographe ?"
    a: "Les domaines peuvent contenir des lettres non latines, stockées sous une forme ASCII commençant par `xn--`. Les attaquants enregistrent des sosies comme `аpple.com` avec un а cyrillique, presque identique à l'original à l'écran. LinkHazmat convertit l'hôte en ASCII : toute étiquette `xn--` est démasquée et signalée."
  - q: "Pourquoi un @ dans une URL est-il suspect ?"
    a: "Tout ce qui précède un `@` dans la partie autorité d'une URL est traité comme un nom d'utilisateur, pas comme un hôte. `https://www.bank.com@evil.example/` mène en réalité à `evil.example`. Les liens légitimes ne l'utilisent quasiment jamais, d'où les deux points ajoutés par l'outil."
  - q: "Quels TLD sont signalés ?"
    a: "`.xyz`, `.top`, `.gq`, `.zip`, `.mov`, `.tk`, `.ml`, `.ga`, `.cf`, `.buzz`, `.icu` et `.cam` : des extensions bon marché ou gratuites qui apparaissent de façon disproportionnée dans les signalements d'abus. Beaucoup de sites honnêtes les utilisent, elles n'ajoutent donc qu'un point."
---

## Comment ça marche

La saisie est analysée avec le constructeur standard `URL` du navigateur (en ajoutant `http://` si le schéma manque). On obtient ainsi le protocole, le nom d'hôte sous forme ASCII et la chaîne de requête exactement comme un navigateur les interpréterait, ce qui est essentiel car le phishing vit de l'écart entre ce à quoi une URL *ressemble* et là où elle *mène*.

Chaque contrôle ajoute des points à un score de risque :

| Contrôle | Ce qu'il cherche | Points |
|---|---|---|
| Non chiffré | `http:` au lieu de `https:` | +1 |
| Hôte IP | un hôte comme `185.12.4.9` au lieu d'un domaine | +2 |
| Connexion cachée | un `@` n'importe où dans la saisie | +2 |
| TLD à risque | une des 12 extensions souvent détournées | +1 |
| Domaine long | nom d'hôte de plus de 50 caractères | +1 |
| Imbrication profonde | plus de 4 étiquettes, ex. `a.b.c.d.com` | +1 |
| Punycode | une étiquette commençant par `xn--` (sosie internationalisé) | +2 |
| Beaucoup de tirets | 3 tirets ou plus dans le nom d'hôte | +1 |
| Paramètre de redirection | `redirect=`, `url=`, `goto=`, `next=`, `redir=` ou `link=` dans la requête | +1 |
| Marque en sous-domaine | paypal, apple, google, microsoft, amazon, netflix, bank, secure, login, verify ou account à *gauche* du domaine enregistrable | +2 |

Un score de **0** correspond à *LOW RISK*, **1–2** à *SUSPICIOUS*, **3 ou plus** à *HIGH RISK*. Le contrôle des marques ne regarde que les étiquettes de sous-domaine : `www.paypal.com` passe, tandis que `paypal.com.account-check.xyz` (domaine enregistrable `account-check.xyz`) est signalé. Le domaine enregistrable est approximé par les deux dernières étiquettes ; les suffixes composés comme `.co.uk` comptent donc un niveau de moins.

Les boutons d'analyse approfondie construisent des liens vers la recherche de VirusTotal, le statut Safe Browsing de Google et la recherche d'urlscan.io, avec votre domaine ou votre URL encodés. Ils ne s'ouvrent, dans un nouvel onglet, que si vous cliquez.

## Cas d'usage

- **Vérifier un lien reçu par e-mail ou SMS** prétendant venir de votre banque, d'un transporteur ou d'un service de streaming, avant de décider d'y toucher.
- **Support et SOC.** Donnez à un collègue une lecture structurelle rapide d'un lien signalé, puis passez aux scanners de réputation.
- **Sensibilisation à la sécurité.** Collez des exemples réels de phishing et montrez les ruses employées par chacun.
- **Liens issus de QR codes.** Lisez un QR code avec l'appareil photo sans l'ouvrir, puis collez d'abord l'URL ici.
- **Relire vos propres liens.** Assurez-vous que vos liens marketing avec paramètres de suivi ou de redirection ne ressemblent pas à du phishing pour les utilisateurs prudents.
