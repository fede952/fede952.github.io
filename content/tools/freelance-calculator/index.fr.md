---
title: "Calculateur de Taux Horaire Freelance"
description: "Calculez le taux horaire et le TJM dont vous avez besoin en freelance à partir du net visé, des jours et heures facturables, des impôts et des frais."
intro: "**RateMate** transforme le revenu que vous voulez garder en tarif à facturer. Saisissez le salaire net annuel visé, vos jours et heures facturables, votre taux d'imposition et vos frais mensuels, et obtenez aussitôt votre taux horaire, votre taux journalier et le chiffre d'affaires mensuel à atteindre."
date: 2026-02-03
lastmod: 2026-10-24
reviewed: false
keywords: ["calcul taux horaire freelance", "calculer tjm", "combien facturer en freelance", "calculateur tjm", "tarif freelance", "taux horaire indépendant", "tarif consultant", "calcul tarif auto-entrepreneur"]
tags: ["freelance", "finances", "business", "outil"]
app_category: "FinanceApplication"
tool_file: "/tools/freelance-calculator/"
tool_title: "RateMate, calculateur de tarif freelance"
tool_height: 900
tool_sandbox: "allow-scripts allow-same-origin"
howto:
  - "Choisissez la devise ($, € ou £) et saisissez le **Desired Annual Net Salary** : ce que vous voulez garder après impôts et frais professionnels."
  - "Réglez **Billable Days per Year**. La valeur par défaut est 220 ; retirez honnêtement congés, maladie, administratif et prospection."
  - "Réglez **Daily Billable Hours** : les heures réellement facturables, en général 5 à 7 plutôt que 8."
  - "Placez le curseur **Tax Rate** sur votre taux effectif d'impôts et de cotisations, puis saisissez vos **Monthly Expenses** (logiciels, matériel, assurances, coworking, comptable)."
  - "Lisez **Your Hourly Rate**, le **Daily Rate** (votre TJM) et le **Monthly Gross** à facturer. Le graphique en anneau montre comment chaque euro facturé se répartit entre revenu, impôts et frais."
faq:
  - q: "Comment calculer son taux horaire en freelance ?"
    a: "Partez du revenu dont vous avez besoin, pas de ce que facturent les autres. Ajoutez vos frais professionnels annuels, remontez le total au brut pour les impôts, puis divisez par les heures que vous pouvez réellement facturer. Avec les valeurs par défaut (60 000 net, 500 de frais par mois, 25 % d'impôts, 220 jours de 6 heures facturables) : (60 000 + 6 000) ÷ 0,75 = 88 000 par an, 400 par jour, environ 67 de l'heure."
  - q: "Combien de jours facturables par an faut-il prévoir ?"
    a: "Une année compte environ 260 jours ouvrés. Retirez les jours fériés (8 à 14 selon le pays), 20 à 25 jours de congés, quelques jours de maladie et le temps consacré à la prospection, à l'administratif et à la formation. La plupart des freelances se situent entre 180 et 220 jours facturables ; les débutants sans clientèle régulière facturent souvent moins."
  - q: "Pourquoi les heures facturables sont-elles inférieures aux heures travaillées ?"
    a: "E-mails, factures, devis, réunions non facturables et changements de contexte prennent du temps. Six heures facturables sur une journée de huit est un chiffre courant et tenable. Si vous facturez huit heures chaque jour, vous en travaillez probablement dix."
  - q: "Quel taux d'imposition saisir ?"
    a: "Votre taux *effectif* : impôt sur le revenu plus cotisations sociales, divisés par le chiffre d'affaires brut, et non votre tranche marginale. Il varie énormément selon le pays et le statut (en France, entre micro-entreprise et société, par exemple) ; pour une première estimation, prenez les chiffres de l'an dernier ou demandez à votre comptable, puis testez plusieurs valeurs."
  - q: "Le calculateur considère-t-il les frais comme déductibles ?"
    a: "Non. Il applique le taux à tout le brut, frais compris, ce qui donne un tarif un peu plus élevé et plus prudent. Si vos frais sont entièrement déductibles, le brut nécessaire vaut plutôt net ÷ (1 − taux) + frais : avec les valeurs par défaut, 86 000 au lieu de 88 000, soit environ 65 de l'heure au lieu de 67."
  - q: "Facturer à l'heure, à la journée ou au projet ?"
    a: "Utilisez le taux horaire comme plancher. Beaucoup de freelances proposent un TJM (affiché ici) ou un forfait par projet calculé à partir de celui-ci, qui récompense l'efficacité plutôt que les heures. Quel que soit votre devis, vérifiez qu'il ne descend jamais sous le taux horaire de ce calculateur."
  - q: "Mes données financières sont-elles enregistrées ?"
    a: "Non. Le calcul se fait dans votre navigateur, rien n'est enregistré ni envoyé. Fermez la page et les chiffres disparaissent."
---

## Comment ça marche

RateMate raisonne à rebours, à partir de l'argent que vous voulez garder.

1. **Frais annuels** = frais mensuels × 12.
2. **Chiffre d'affaires annuel nécessaire** = (net visé + frais annuels) ÷ (1 − taux d'imposition).
   Le taux est traité comme une part fixe de tout ce que vous facturez : la formule remonte donc au brut à la fois votre salaire et vos frais.
3. **Impôts annuels** = brut − net − frais.
4. **Taux journalier** = brut ÷ jours facturables.
5. **Taux horaire** = taux journalier ÷ heures facturables par jour.
6. **Brut mensuel** = brut ÷ 12, soit ce que vous devez facturer en moyenne chaque mois.

Le graphique en anneau, tracé avec Chart.js, montre les trois parts du brut : revenu net, impôts et frais. Chaque champ recalcule à la saisie : faites glisser le curseur d'imposition (0–60 %) et regardez le tarif bouger.

### Exemple chiffré

| Donnée | Valeur |
|---|---|
| Net visé | 60 000 |
| Frais mensuels | 500 (6 000 par an) |
| Taux d'imposition | 25 % |
| Jours facturables | 220 |
| Heures facturables par jour | 6 |

Brut = 66 000 ÷ 0,75 = **88 000** par an → **400** par jour → **≈ 67** de l'heure → **≈ 7 333** à facturer par mois. Sur 100 facturés, environ 68 sont du revenu, 25 des impôts et 7 couvrent les frais.

Changez une seule hypothèse et vous comprendrez pourquoi les tarifs varient autant. À 180 jours facturables, le taux horaire monte à environ 81 ; à 5 heures facturables par jour au lieu de 6, à 80. Le levier le plus puissant n'est généralement pas le taux d'imposition, mais la part de votre temps que vous facturez vraiment.

### Ce que le modèle ne prend pas en compte

Le calculateur s'en tient volontairement à un seul taux effectif. Il ne modélise ni les tranches progressives, ni la TVA (qui s'ajoute à votre tarif et que vous reversez), ni l'épargne retraite au-delà de ce que vous incluez dans le « net », ni les périodes non facturées entre deux missions. Si elles vous concernent, ajoutez une marge ou augmentez le net visé.

## Cas d'usage

- **Se lancer en freelance.** Traduisez votre salaire de salarié en tarif nécessaire, et voyez tout de suite pourquoi un freelance doit facturer bien plus que salaire ÷ 2 080 heures.
- **Préparer un devis.** Vérifiez qu'un forfait projet, divisé par le nombre de jours qu'il demande, reste au-dessus de votre TJM.
- **Augmenter ses tarifs.** Saisissez les frais et le taux réels de cette année et vérifiez que votre tarif actuel les couvre toujours.
- **Comparer des offres.** Comparez le TJM d'une mission et un salaire en CDI à conditions égales.
- **Préparer une année sabbatique ou une formation.** Réduisez les jours facturables et voyez de combien votre tarif doit augmenter pour garder le même revenu.
