---
title: "SafeEnv : Scanner de Secrets et Clés API pour Fichiers .env"
description: "Analysez vos fichiers .env et extraits de configuration à la recherche de secrets exposés avant de committer — clés AWS, tokens GitHub et Stripe, clés privées, mots de passe dans les URLs et valeurs à haute entropie. 100% dans votre navigateur : rien n'est jamais envoyé."
date: 2026-07-05
tags: ["security", "developer-tools", "secrets", "privacy"]
keywords: ["scanner fichier env", "scanner de secrets", "vérifier clés api", "détecter secrets exposés", "analyser env", "fuite clés aws", "git secrets", "scanner de secrets côté client", "sécurité dotenv"]
layout: "tool"
draft: false
tool_file: "/tools/secrets-scanner/"
tool_height: "1150"
schema_json: >
  {"@context": "https://schema.org", "@type": "SoftwareApplication", "name": "SafeEnv — Scanner de Secrets et Clés API", "description": "Scanner gratuit côté client qui trouve les clés API, tokens, clés privées et mots de passe exposés dans les fichiers .env et configurations avant le commit.", "applicationCategory": "SecurityApplication", "operatingSystem": "Web", "browserRequirements": "Requires JavaScript", "isAccessibleForFree": true, "offers": {"@type": "Offer", "price": "0", "priceCurrency": "USD"}}
---

## Pourquoi analyser avant de committer

Un seul `.env` collé dans un dépôt public suffit : des bots parcourent GitHub et trouvent les clés AWS fraîches en **moins d'une minute**. SafeEnv attrape la fuite avant le commit. Collez n'importe quelle configuration — `.env`, `docker-compose.yml`, config CI, extraits de code — et il signale les identifiants exposés avec le numéro de ligne, un aperçu masqué et des étapes concrètes de remédiation.

L'analyse s'exécute entièrement dans la mémoire de cette page. Aucun envoi, aucun journal, aucune requête réseau — le seul design acceptable pour un outil où l'on colle de vrais secrets. Rechargez la page et tout disparaît.

## Ce qu'il détecte

- **Tokens cloud et API** — clés AWS, GitHub, GitLab, Stripe, Google, OpenAI, Anthropic, Slack, SendGrid, npm, PyPI, Telegram, Twilio
- **Clés privées** — blocs PEM RSA/EC/OpenSSH/PGP
- **Identifiants dans les URLs** — chaînes de connexion aux bases de données et URLs basic-auth avec mots de passe intégrés
- **Fuites génériques** — mots de passe codés en dur et valeurs à haute entropie, avec détection des placeholders pour limiter les faux positifs

Collez une configuration pour l'analyser, ou chargez l'exemple pour voir tous les détecteurs se déclencher sur de fausses clés.
