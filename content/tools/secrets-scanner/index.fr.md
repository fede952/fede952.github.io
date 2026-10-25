---
title: "Secrets Scanner : Trouver des Clés d'API"
description: "Collez un .env, un fichier de configuration ou du code et repérez clés d'API, tokens, clés privées et mots de passe exposés avant le commit. 100 % local."
intro: "**SafeEnv** recherche les identifiants exposés dans un texte : clés AWS, GitHub, Stripe, OpenAI et Slack, blocs de clés privées, mots de passe dans des chaînes de connexion et valeurs à forte entropie à côté de noms comme `SECRET` ou `TOKEN`. Collez ou déposez un fichier : l'analyse se fait entièrement dans votre navigateur."
date: 2026-07-05
lastmod: 2026-10-24
reviewed: false
keywords: ["secrets scanner", "trouver clé api dans le code", "scanner fichier env", "mot de passe en dur", "détecter identifiants exposés", "fuite token github", "détection de secrets en ligne", "clé api exposée"]
tags: ["sécurité", "devsecops", "secrets", "outil"]
app_category: "DeveloperApplication"
tool_file: "/tools/secrets-scanner/"
tool_title: "SafeEnv, scanner de secrets"
tool_height: 1000
tool_sandbox: "allow-scripts allow-same-origin"
tool_allow: "clipboard-write"
howto:
  - "Collez dans le champ le contenu d'un `.env`, d'un `docker-compose.yml`, d'une configuration CI, d'un fichier Terraform ou d'un extrait de code, ou utilisez **Scan a file…**, ou glissez un fichier dessus."
  - "Cliquez sur **Scan for secrets**. Un fichier de configuration typique est analysé en quelques millisecondes."
  - "Lisez les pastilles de synthèse (critical, high, medium, low, info) et la liste des résultats, triée par gravité puis par numéro de ligne."
  - "Chaque résultat indique la règle déclenchée, la ligne, une valeur masquée (seulement les quatre premiers et les quatre derniers caractères) et la marche à suivre."
  - "Traitez d'abord les critiques : faites tourner l'identifiant, retirez-le du fichier et de l'historique git, et chargez-le depuis un gestionnaire de secrets ou une variable d'environnement. **Copy report** fournit un résumé texte pour un ticket."
faq:
  - q: "Puis-je coller de vrais secrets dans ce scanner sans risque ?"
    a: "Le scanner est du JavaScript exécuté dans cette page et n'envoie votre texte dans aucune requête réseau : rien n'atteint nos serveurs. L'écran n'affiche que des valeurs masquées, jamais les secrets complets. Cela dit, si vous trouvez une vraie clé de production, considérez-la comme compromise et renouvelez-la."
  - q: "Quels types de secrets détecte-t-il ?"
    a: "Vingt formats précis, dont les access key ID et secret keys AWS, les tokens GitHub et GitLab, les clés Stripe live et de test, les clés d'API Google, OpenAI et Anthropic, les tokens et webhooks Slack, les clés SendGrid, npm, PyPI, bot Telegram et Twilio, les JSON Web Tokens, les blocs de clés privées et les identifiants dans des URL de base de données ou HTTP. Un second passage signale les valeurs à forte entropie et les mots de passe en dur dans toute ligne `CLÉ=VALEUR`."
  - q: "Pourquoi une valeur est-elle marquée « high entropy » ?"
    a: "Les chaînes d'apparence aléatoire ressemblent précisément à des secrets générés. Le scanner calcule l'entropie de Shannon de chaque valeur d'au moins 20 caractères et la signale à partir de 4,3 bits par caractère. Les valeurs placées à côté de noms contenant secret, token, password, key ou auth sont classées plus haut. Des hachages, UUID ou identifiants de build peuvent aussi le déclencher : regardez le contexte."
  - q: "Que faire si un secret a été commité dans git ?"
    a: "Supprimer la ligne dans un nouveau commit ne suffit pas : le secret reste dans l'historique et dans chaque clone. Faites d'abord tourner ou révoquez l'identifiant, puis réécrivez l'historique avec `git filter-repo` ou BFG Repo-Cleaner, faites un force-push et demandez aux collaborateurs de recloner. C'est la rotation qui vous protège vraiment."
  - q: "Remplace-t-il des outils comme Gitleaks ou le secret scanning de GitHub ?"
    a: "Non, il les complète. Utilisez un hook pre-commit ou un scanner en CI pour chaque commit, et la push protection de GitHub sur vos dépôts. SafeEnv sert entre deux : vérifier un extrait avant de le coller dans un chat, un ticket ou un assistant IA, ou relire une configuration qu'on vous a envoyée."
  - q: "Pourquoi les valeurs factices apparaissent-elles en info ?"
    a: "Des lignes comme `API_KEY=your-api-key-here` ou `PASSWORD=${DB_PASSWORD}` ont la forme d'un secret mais sont des modèles. Le scanner reconnaît les motifs de valeurs factices courants (your-, changeme, example, xxx, `${VAR}`, `<value>`) et les signale en info pour que vous confirmiez qu'ils sont voulus."
---

## Comment ça marche

Le scanner est un petit moteur de règles sans dépendance. Il fait deux passages sur le texte.

### Passage 1 : formats de tokens connus

Vingt expressions régulières reconnaissent des formats que les fournisseurs documentent publiquement, surtout grâce à un préfixe fixe et une longueur. Quelques exemples de ce que cherchent les règles :

| Règle | Signature reconnue | Gravité |
|---|---|---|
| Bloc de clé privée | `-----BEGIN … PRIVATE KEY-----` (RSA, EC, DSA, OpenSSH, PGP, chiffrée) | Critique |
| Access key ID AWS | `AKIA`, `ASIA`, `ABIA` ou `ACCA` suivis de 16 majuscules ou chiffres | Critique |
| Secret access key AWS | Une valeur Base64 de 40 caractères affectée à un nom comme `aws_secret_access_key` | Critique |
| Token GitHub | Préfixes `ghp_`, `gho_`, `ghu_`, `ghs_`, `ghr_` ou `github_pat_` | Critique |
| Clé Stripe live | Préfixes `sk_live_` / `rk_live_` | Critique |
| Clé OpenAI / Anthropic | Préfixes `sk-proj-`, `sk-svcacct-`, `sk-ant-` | Critique |
| Clé d'API Google | `AIza` suivi de 35 caractères | Élevée |
| Token / webhook Slack | Tokens `xox[baprs]-`, URL `hooks.slack.com/services/…` | Élevée |
| Identifiants dans une URI | `postgres://utilisateur:motdepasse@hôte`, ainsi que MySQL, MongoDB, Redis, AMQP, FTP et basic auth HTTP | Élevée |
| JSON Web Token | Trois segments Base64URL commençant par `eyJ` | Moyenne |
| Clé Stripe de test / publique | `sk_test_`, `pk_live_`, `pk_test_` | Faible |

Chaque correspondance enregistre le numéro de ligne (calculé d'après les retours à la ligne qui précèdent) et une version **masquée** de la valeur qui ne garde que les quatre premiers et les quatre derniers caractères : le rapport ne contient donc jamais le secret.

### Passage 2 : analyse générique `CLÉ=VALEUR`

Les lignes qu'aucune règle spécifique n'a captées sont lues comme des affectations, la syntaxe des `.env`, du YAML et de la plupart des formats de configuration (préfixes `export`, guillemets et commentaires `#` en fin de ligne sont gérés). Pour chaque valeur d'au moins six caractères :

1. Si elle ressemble à une **valeur factice** (`your-…`, `changeme`, `example`, `xxxx`, `${VAR}`, `<value>`, `true/false/null`), elle est signalée en *info* quand le nom de clé évoque un secret, sinon ignorée.
2. Les valeurs contenant une URL ou des espaces sont ignorées, car elles sont rarement des secrets à elles seules.
3. L'**entropie de Shannon** H = −Σ p·log₂(p) est calculée sur les fréquences des caractères. Une valeur de 20 caractères ou plus avec H ≥ 4,3 bits par caractère est marquée *high entropy*, en gravité élevée si le nom de la clé contient secret, token, passw, pwd, api_key, private, credential ou auth, moyenne sinon.
4. Une valeur d'entropie plus faible affectée à un nom de type mot de passe est signalée comme *hardcoded password*.

Les résultats sont triés par gravité, puis par ligne. Rien n'est conservé : videz le champ ou fermez l'onglet, et le texte disparaît.

### Limites

L'analyse par regex trouve des *formats*, pas une *validité* : elle ne peut pas savoir si une clé est encore active. Elle ne voit pas non plus les secrets répartis sur plusieurs lignes, chiffrés ou encodés de manière inhabituelle. C'est donc une vérification rapide, pas un substitut à l'analyse dans votre pipeline CI.

## Cas d'usage

- **Avant de partager un extrait.** Vérifiez une configuration ou une stack trace avant de la coller dans Slack, une issue GitHub, Stack Overflow ou un chatbot IA.
- **Avant le premier commit.** Analysez le `.env.example`, le `docker-compose.yml` et les fichiers CI d'un nouveau projet pour vous assurer qu'aucune vraie valeur ne s'y est glissée.
- **Relecture d'une pull request ou d'une passation.** Collez le diff des fichiers de configuration et cherchez tout ce qui est critique.
- **Réponse à incident.** Après une fuite présumée, analysez des journaux ou configurations exportés pour lister tous les identifiants à renouveler.
- **Transmettre de bonnes habitudes.** Le fichier d'exemple montre à une équipe, en quelques secondes, combien de secrets contient un `.env` ordinaire.
