---
title: "Analyser les en-têtes d'un e-mail"
description: "Collez les en-têtes d'un e-mail pour retracer chaque serveur, vérifier SPF, DKIM et DMARC et repérer les expéditeurs usurpés. Gratuit, privé, en local."
intro: "Collez les **en-têtes bruts** d'un e-mail suspect pour voir d'où il vient vraiment. L'analyseur reconstruit le **parcours serveur par serveur** avec le délai de chaque étape, lit les résultats **SPF, DKIM, DMARC et ARC** notés par votre fournisseur et signale les **incohérences** entre From, Reply-To et Return-Path. Tout est analysé dans votre navigateur : les en-têtes ne sont envoyés nulle part."
date: 2026-10-26
lastmod: 2026-10-26
reviewed: false
keywords: ["analyser en-tête email", "lire les en-têtes d'un mail", "vérifier l'expéditeur d'un mail", "savoir si un mail est frauduleux", "gmail afficher l'original en-têtes", "vérifier spf dkim dmarc mail", "retracer l'origine d'un email", "détecter usurpation email"]
tags: ["security", "email", "phishing", "tool"]
app_category: "SecurityApplication"
tool_file: "/tools/email-header-analyzer/"
tool_title: "Analyseur d'en-têtes d'e-mail"
tool_height: 1100
tool_sandbox: "allow-scripts allow-same-origin"
howto:
  - "Copiez les en-têtes bruts depuis votre messagerie (voir **Comment obtenir les en-têtes** ci-dessous) — ou toute la source du message, le corps est ignoré."
  - "Collez-les dans la zone. L'analyse se lance au collage ; appuyez sur **Analyser** pour la relancer."
  - "Lisez le **verdict** et les **signaux**, du plus grave au moins grave. Chacun explique ce qu'il signifie et quand il est sans danger."
  - "Vérifiez le tableau **Identité de l'expéditeur** : les domaines de From, Reply-To et Return-Path appartiennent normalement à la même organisation."
  - "Suivez le **parcours** du premier serveur jusqu'à votre boîte. Les longs délais et les serveurs inattendus méritent un second regard."
faq:
  - q: "Mes en-têtes sont-ils envoyés quelque part ?"
    a: "Non. Les en-têtes sont analysés par le JavaScript de cette page et l'outil ne fait aucune requête réseau. Vous pouvez ouvrir la page, vous déconnecter d'internet, et il fonctionne toujours."
  - q: "L'analyseur peut-il dire avec certitude qu'un e-mail est de l'hameçonnage ?"
    a: "Aucun outil ne le peut. Les en-têtes montrent comment le message a voyagé et si le domaine de l'expéditeur s'en porte garant. Un message peut réussir tous les contrôles et être quand même une arnaque envoyée depuis un domaine ressemblant appartenant à l'escroc : regardez aussi le domaine du From et les liens (l'outil Link Hazmat de ce site les vérifie)."
  - q: "Pourquoi certains en-têtes ne sont-ils pas jugés fiables ?"
    a: "Tout ce qui se trouve sous les lignes Received ajoutées par votre fournisseur peut être écrit par n'importe qui en chemin, y compris l'expéditeur. L'analyseur fait confiance à l'en-tête Authentication-Results de votre fournisseur et traite le reste comme des affirmations. Pour un message transféré en pièce jointe, analysez l'original joint, pas le message de transfert."
  - q: "Que signifient SPF, DKIM et DMARC ?"
    a: "SPF indique quels serveurs peuvent envoyer du courrier pour un domaine. DKIM est une signature cryptographique ajoutée par le domaine d'envoi. DMARC réussit quand SPF ou DKIM réussit pour le même domaine que celui du From, et indique aux destinataires quoi faire quand aucun ne réussit. ARC conserve les résultats d'origine quand une liste ou un transfert modifie le message."
  - q: "Pourquoi une vraie lettre d'information a-t-elle un autre Return-Path ?"
    a: "Les services d'envoi expédient pour le compte d'entreprises et récupèrent les retours d'erreur sur leur propre domaine ou un sous-domaine. C'est pourquoi un Return-Path ou un Message-ID d'un autre domaine n'est signalé qu'en faible : il compte quand il s'accompagne d'un échec DMARC ou d'un Reply-To vers un domaine sans rapport."
  - q: "Pourquoi certaines heures reculent-elles ?"
    a: "Chaque serveur note l'heure de sa propre horloge, et certaines horloges sont fausses. L'analyseur le signale comme un décalage d'horloge et affiche quand même le parcours dans l'ordre."
---

## Comment obtenir les en-têtes

La plupart des messageries masquent les en-têtes. Ouvrez d'abord le message, puis :

- **Gmail (web)** — ouvrez le message, cliquez sur le bouton **⋮ Plus** à côté de Répondre et choisissez **Afficher l'original**. Appuyez sur **Copier dans le presse-papiers**. L'application Gmail sur téléphone n'affiche pas les en-têtes : utilisez un navigateur.
- **Outlook pour Windows (classique)** — double-cliquez sur le message pour l'ouvrir dans sa fenêtre, puis **Fichier → Propriétés**. Les en-têtes sont dans la zone **En-têtes Internet** en bas : cliquez dedans, puis Ctrl+A et Ctrl+C.
- **Nouvel Outlook et Outlook sur le web** — ouvrez le message, cliquez sur **… Autres actions → Afficher → Afficher les détails du message** et copiez le texte.
- **Apple Mail (Mac)** — sélectionnez le message et choisissez **Présentation → Message → Tous les en-têtes** (⇧⌘H), ou **Présentation → Message → Source brute** (⌥⌘U) pour le message complet. Mail sur iPhone et iPad n'affiche pas les en-têtes.
- **Thunderbird** — sélectionnez le message et choisissez **Affichage → Source du message** (Ctrl+U, ⌘U sur Mac). Copiez tout ce qui précède la première ligne vide, ou simplement tout.

Les noms des menus peuvent varier légèrement selon la version. Ne vous transférez pas l'e-mail suspect pour voir ses en-têtes : le transfert crée un nouveau message avec de nouveaux en-têtes.

## Comment ça marche

### Le parcours : les lignes Received se lisent de bas en haut

Chaque serveur qui traite un message ajoute une ligne **Received** en haut : la plus ancienne est donc en bas. L'analyseur les inverse en une chronologie du premier serveur jusqu'à votre boîte et affiche le temps passé entre les étapes. Seules les lignes ajoutées par votre propre fournisseur sont fiables : un expéditeur peut écrire de fausses lignes Received en dessous. C'est pourquoi l'analyseur s'appuie sur les résultats d'authentification et non sur l'origine annoncée.

### Authentification : ce que votre fournisseur a déjà vérifié

À l'arrivée d'un message, votre fournisseur vérifie **SPF**, **DKIM** et **DMARC** et note les résultats dans l'en-tête **Authentication-Results**. L'analyseur lit cet en-tête et vérifie aussi l'**alignement** : une signature DKIM ou un SPF réussi ne vous protègent que s'ils concernent la même organisation que l'adresse From. Il n'interroge pas le DNS et ne vérifie pas lui-même les signatures, car votre fournisseur l'a déjà fait à la livraison, avec les clés valables à ce moment-là.

### Incohérences d'identité

Le nom affiché est du texte libre : les escrocs y placent souvent une adresse de confiance (`"aide@votrebanque.example" <x@random.test>`). L'analyseur compare les domaines de **From**, **Reply-To**, **Return-Path** et du **Message-ID**, et explique quelles différences sont normales pour les services d'envoi et lesquelles trahissent un imposteur.

## Cas d'usage

- **Un e-mail suspect** — vérifiez que le message de la « banque » ou du « livreur » vient vraiment de ce domaine avant de cliquer quoi que ce soit.
- **Support et équipes sécurité** — triez vite les signalements d'hameçonnage et collez la chronologie dans un ticket.
- **Délivrabilité** — comprenez pourquoi vos propres lettres d'information échouent à DMARC ou finissent en spam, et quelle étape retarde la livraison.
- **Pour apprendre** — comprenez SPF, DKIM et DMARC avec des exemples réalistes, puis testez-vous avec le [quiz sur l'hameçonnage](../phishing-quiz/).
