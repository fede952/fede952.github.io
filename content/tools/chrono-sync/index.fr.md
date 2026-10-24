---
title: "Convertisseur Timestamp Unix (Epoch → Date)"
description: "Convertissez des timestamps Unix en dates et des dates en epoch, en UTC et en heure locale. Secondes ou millisecondes détectées. Horloge epoch en direct."
intro: "**ChronoSync** convertit les **timestamps Unix (epoch)** en dates lisibles et inversement. Il affiche le timestamp actuel en direct, accepte secondes ou millisecondes et donne chaque résultat en UTC et dans votre fuseau horaire."
date: 2026-02-03
lastmod: 2026-10-24
reviewed: false
keywords: ["convertisseur timestamp unix", "convertir epoch", "timestamp en date", "date en timestamp", "epoch time maintenant", "temps unix", "millisecondes en date", "convertisseur epoch"]
tags: ["outils-développeur", "temps", "convertisseur", "outil"]
app_category: "DeveloperApplication"
tool_file: "/tools/chrono-sync/"
tool_title: "ChronoSync, convertisseur de timestamps Unix"
tool_height: 700
tool_sandbox: "allow-scripts allow-same-origin"
tool_allow: "clipboard-write"
howto:
  - "Lisez le **Timestamp UNIX Actuel** en haut : il se met à jour chaque seconde, avec le même instant en UTC en dessous."
  - "Pour transformer un timestamp en date, collez-le dans **Timestamp → Date** et cliquez sur **Convertir**. Les valeurs à 10 chiffres sont lues comme des secondes, celles à 13 chiffres comme des millisecondes."
  - "Lisez le résultat : d'abord la date en UTC, puis le même instant dans le fuseau local de votre navigateur."
  - "Pour obtenir un timestamp, choisissez date et heure dans **Date → Timestamp** (heure locale, à la seconde) et cliquez sur **Convertir**."
  - "Utilisez le petit bouton de copie à côté de chaque résultat pour le placer dans le presse-papiers."
faq:
  - q: "Qu'est-ce qu'un timestamp Unix ?"
    a: "Le nombre de secondes écoulées depuis le 1er janvier 1970 à 00:00:00 UTC, l'« epoch » Unix, sans compter les secondes intercalaires. À un instant donné il est le même partout sur Terre, c'est pourquoi serveurs, bases de données et journaux l'utilisent : 1700000000 correspond au 14 novembre 2023 à 22:13:20 UTC, quel que soit votre fuseau."
  - q: "Secondes ou millisecondes ?"
    a: "Les outils Unix, PHP, `time.time()` de Python (en entier) et la plupart des bases de données utilisent les secondes, aujourd'hui 10 chiffres. `Date.now()` en JavaScript, `System.currentTimeMillis()` en Java et beaucoup d'API utilisent les millisecondes, 13 chiffres. ChronoSync traite les saisies de 13 chiffres ou plus comme des millisecondes et l'indique par (ms)."
  - q: "Pourquoi ma date convertie semble-t-elle décalée d'une ou deux heures ?"
    a: "Parce qu'un timestamp n'a pas de fuseau horaire : seul son affichage en a un. Comparez la ligne UTC, pas la ligne locale, avec votre serveur ou vos journaux, généralement en UTC. Le passage à l'heure d'été explique les écarts qui n'apparaissent qu'une partie de l'année."
  - q: "Qu'est-ce que le problème de l'an 2038 ?"
    a: "Les systèmes qui stockent les timestamps en entiers signés sur 32 bits débordent à 2147483647, soit le 19 janvier 2038 à 03:14:07 UTC. La valeur devient alors négative et les dates repartent en 1901. Les systèmes modernes utilisent 64 bits, mais les équipements embarqués et les vieux formats de fichiers restent concernés."
  - q: "Est-ce que ça marche pour les dates avant 1970 ?"
    a: "Oui. Les timestamps négatifs comptent les secondes avant l'epoch : -86400 correspond au 31 décembre 1969 à 00:00 UTC. Saisissez le signe moins et convertissez normalement."
  - q: "Comment obtenir le timestamp actuel dans du code ?"
    a: "Bash : `date +%s`. Python : `int(time.time())`. JavaScript : `Math.floor(Date.now() / 1000)`. PHP : `time()`. SQL (PostgreSQL) : `extract(epoch from now())`. PowerShell : `[DateTimeOffset]::UtcNow.ToUnixTimeSeconds()`."
---

## Comment ça marche

Tout repose sur du JavaScript et l'objet `Date` du navigateur, qui stocke le temps en interne en millisecondes depuis l'epoch.

**Horloge en direct.** Chaque seconde, la page calcule `Math.floor(Date.now() / 1000)` et l'affiche à côté du `toISOString()` du même instant, au format `AAAA-MM-JJ HH:MM:SS UTC`.

**Timestamp → date.** La saisie doit être un entier, éventuellement négatif. S'il compte 13 chiffres ou plus, il est considéré en millisecondes ; sinon il est multiplié par 1000. La `Date` obtenue est affichée deux fois :

1. en **UTC**, via `toISOString()`, la forme sans ambiguïté à comparer aux journaux et aux serveurs ;
2. en **heure locale**, via `toLocaleString()`, avec le fuseau et le format de date de votre navigateur.

**Date → timestamp.** Le sélecteur est un `<input type="datetime-local">`, sans fuseau propre : le navigateur l'interprète dans votre fuseau local. `getTime() / 1000`, arrondi à l'inférieur, donne les secondes epoch. Le sélecteur est prérempli avec l'heure locale actuelle.

| Timestamp | Date UTC | Remarque |
|---|---|---|
| `0` | 1970-01-01 00:00:00 | L'epoch |
| `1000000000` | 2001-09-09 01:46:40 | Premier timestamp à 10 chiffres |
| `1700000000` | 2023-11-14 22:13:20 | |
| `2000000000` | 2033-05-18 03:33:20 | |
| `2147483647` | 2038-01-19 03:14:07 | Plus grande valeur signée sur 32 bits |
| `-86400` | 1969-12-31 00:00:00 | Un jour avant l'epoch |

Les secondes intercalaires ne font pas partie du temps Unix : un timestamp correspond donc à un seul instant UTC (hormis la rare seconde intercalaire elle-même), et deux timestamps diffèrent exactement de leur nombre de secondes.

## Cas d'usage

- **Lire des journaux et des JWT.** Transformez `exp`, `iat` et des champs comme `1729771200` en une date exploitable.
- **Déboguer les fuseaux horaires.** Voyez d'un coup d'œil si une valeur enregistrée correspond à minuit UTC ou à minuit local.
- **Écrire des requêtes.** Obtenez le timestamp du « 1er mars 2026 00:00 » à coller dans un `WHERE` SQL ou un filtre d'API.
- **Passer d'un langage à l'autre.** Vérifiez qu'une valeur venant de JavaScript (ms) et une de Python (s) désignent le même moment.
- **Cron et planification.** Contrôlez quand une tâche planifiée en temps epoch s'exécutera réellement.
