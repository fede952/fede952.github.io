---
title: "Générateur Cron : Créer et Expliquer"
description: "Créez des expressions cron visuellement, traduisez-les en langage clair et voyez les 5 prochaines exécutions. Générateur crontab gratuit pour Linux et CI."
intro: "**EasyCron** construit une expression cron en quelques clics, traduit en langage clair celle que vous avez déjà et liste ses cinq prochaines exécutions. Il couvre la syntaxe crontab standard à cinq champs utilisée par cron sous Linux, les CronJobs Kubernetes et la plupart des planificateurs de CI."
date: 2026-02-03
lastmod: 2026-10-24
reviewed: false
keywords: ["générateur cron", "expression cron", "crontab generator", "cron toutes les 5 minutes", "exemples crontab", "expliquer une expression cron", "planifier une tâche cron", "prochaine exécution cron"]
tags: ["linux", "devops", "cron", "outil"]
app_category: "DeveloperApplication"
tool_file: "/tools/easy-cron/"
tool_title: "EasyCron, générateur d'expressions cron"
tool_height: 1100
tool_sandbox: "allow-scripts allow-same-origin"
tool_allow: "clipboard-write"
howto:
  - "Partez d'un **preset** (toutes les 5 minutes, jours ouvrés à 9 h, mensuel le 1er…) ou de la valeur par défaut `* * * * *`."
  - "Utilisez les onglets **Minute, Hour, Day, Month, Weekday** pour régler chaque champ : toutes les valeurs, un intervalle comme toutes les 15 minutes ou des valeurs précises choisies sur une grille. Des boutons rapides couvrent les cas courants comme les heures de bureau ou les jours ouvrés."
  - "Regardez l'expression, sa description et les **Next 5 runs** se mettre à jour à chaque clic."
  - "Cliquez sur **Copy** et collez l'expression dans votre crontab, votre manifeste CronJob ou votre fichier de CI."
  - "Pour comprendre une planification existante, collez-la dans le **Reverse Translator** et cliquez sur **Parse** : vous obtenez la description et les prochaines exécutions, et le constructeur la charge pour la modifier."
faq:
  - q: "Que signifient les cinq champs d'une expression cron ?"
    a: "Dans l'ordre : minute (0–59), heure (0–23), jour du mois (1–31), mois (1–12) et jour de la semaine (0–6, dimanche = 0). `30 2 * * 1` signifie donc à 02:30 chaque lundi. Un astérisque veut dire « toutes les valeurs » pour ce champ."
  - q: "Comment lancer une tâche cron toutes les 5 minutes ?"
    a: "`*/5 * * * *`. Le `*/5` du champ des minutes signifie une minute sur cinq à partir de 0 : 00, 05, 10 … 55. De même, `0 */2 * * *` s'exécute à l'heure pile toutes les deux heures et `*/15 9-17 * * 1-5` toutes les 15 minutes pendant les heures de bureau en semaine."
  - q: "Que se passe-t-il si je renseigne le jour du mois et le jour de la semaine ?"
    a: "Le cron standard (Vixie) lance la tâche quand *l'un ou l'autre* correspond, pas quand les deux correspondent. `0 9 1 * 1` s'exécute à 09:00 le 1er de chaque mois *et* tous les lundis. Le calcul des prochaines exécutions d'EasyCron suit la même règle, qui surprend beaucoup de monde."
  - q: "Dans quel fuseau horaire sont affichées les prochaines exécutions ?"
    a: "Dans celui de votre navigateur. Un démon cron utilise le fuseau de la machine où il tourne, souvent UTC sur les serveurs et dans les conteneurs. Les CronJobs Kubernetes utilisent celui du contrôleur, sauf si vous définissez `spec.timeZone`. Si votre serveur est en UTC, convertissez avant de vous fier à la liste."
  - q: "EasyCron gère-t-il les secondes, les noms comme MON ou JAN, ou @daily ?"
    a: "Non. Il vise la syntaxe portable à cinq champs : nombres, `*`, plages comme `1-5`, listes comme `1,15`, pas comme `*/10` et plages avec pas comme `0-30/10`. Les secondes façon Quartz et `L`, `W`, `#`, `?` ne sont pas gérés. Écrivez `0 0 * * *` au lieu de `@daily` et utilisez `0` (pas `7`) pour dimanche."
  - q: "Quelque chose est-il envoyé à un serveur ?"
    a: "Non. Le constructeur, la description et le calcul des exécutions sont du JavaScript dans cette page. Seule votre préférence de thème clair ou sombre est enregistrée, dans le localStorage du navigateur."
---

## Comment ça marche

### Construire l'expression

Chacun des cinq champs a son propre état : **every** (`*`), **interval** (`*/n`, avec des choix adaptés à chaque champ comme 5, 10, 15 ou 30 minutes et 2, 3, 4, 6, 8 ou 12 heures) ou des valeurs **précises** choisies sur une grille. En mode précis, les nombres sélectionnés sont triés et reliés par des virgules (`0,15,30,45`). Si toutes les valeurs possibles sont sélectionnées, le champ redevient `*`. Les cinq parties sont reliées par des espaces pour former l'expression finale.

### Analyser et expliquer

Le traducteur inverse découpe l'expression aux espaces et exige exactement cinq champs. Chaque champ est développé en l'ensemble des valeurs qu'il couvre :

| Syntaxe | Exemple | Devient |
|---|---|---|
| `*` | `*` pour les heures | 0, 1, 2 … 23 |
| `*/n` | `*/15` pour les minutes | 0, 15, 30, 45 |
| `a-b` | `1-5` pour les jours de la semaine | lun … ven |
| `a-b/n` | `0-30/10` pour les minutes | 0, 10, 20, 30 |
| liste | `1,15` pour les jours | le 1er et le 15 |

La description (en anglais) est assemblée selon des règles qui sonnent comme on le dirait : `*/5 * * * *` devient « Every 5 minutes », `0 9 * * 1-5` « At 09:00, Monday through Friday », `0 0 1 1 *` « At 00:00, on day 1 of the month, in January ».

### Calculer les prochaines exécutions

À partir d'une minute dans le futur, le calculateur avance dans le temps en sautant des unités entières qui ne peuvent pas correspondre : un mois hors de l'ensemble saute au 1er du mois suivant, un jour qui ne correspond pas saute à minuit le lendemain, une heure qui ne correspond pas à l'heure suivante. Quand mois, jour, heure et minute correspondent, la date est retenue, jusqu'à trouver cinq exécutions ou avoir parcouru quatre ans. C'est pourquoi une planification impossible comme `0 0 31 2 *` (31 février) indique qu'aucune exécution n'est à venir.

Le test du jour suit la vraie sémantique de cron : si un seul des deux champs de jour est restreint, c'est lui qui décide ; si les deux le sont, il suffit que l'un corresponde.

## Cas d'usage

- **Écrire une ligne de crontab** pour des sauvegardes, la rotation des journaux, le renouvellement de certificats ou un script de nettoyage, sans rechercher à nouveau l'ordre des champs.
- **CronJobs Kubernetes et pipelines de CI.** `schedule:` de GitHub Actions, les planifications de pipelines GitLab et `spec.schedule` de Kubernetes utilisent les mêmes cinq champs.
- **Relire la planification de quelqu'un d'autre.** Collez le cryptique `15 3 */2 * *` d'une configuration et lisez « At 03:15, every 2nd day of the month ».
- **Repérer les erreurs avant la production**, comme une tâche prévue « en semaine à 9 h » qui tourne aussi le 1er du mois parce que les deux champs de jour ont été renseignés.
- **Planifier des fenêtres de maintenance.** Vérifiez exactement quand tombent les cinq prochaines exécutions, puis adaptez au fuseau du serveur.
