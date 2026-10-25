---
title: "Convertir HEX, RGB et HSL + Palettes Néon"
description: "Convertissez les couleurs entre HEX, RGB et HSL avec sélecteur et copie en un clic, et générez des palettes néon cyberpunk pour interfaces et affiches."
intro: "**NeonPalette** convertit n'importe quelle couleur entre **HEX, RVB et HSL** pendant que vous la choisissez ou la tapez, et génère des **palettes néon** aléatoires de trois couleurs : cyan, magenta, bleu électrique, rose vif et compagnie, pensées pour les interfaces cyberpunk sombres."
date: 2026-02-03
lastmod: 2026-10-24
reviewed: false
keywords: ["convertir hex en rgb", "rgb en hsl", "convertisseur hex hsl", "convertisseur de couleurs", "palette couleurs néon", "palette cyberpunk", "sélecteur de couleur en ligne", "couleurs néon hex"]
tags: ["design", "css", "couleurs", "outil"]
app_category: "DesignApplication"
tool_file: "/tools/neon-palette/"
tool_title: "NeonPalette, convertisseur de couleurs et générateur de palettes"
tool_height: 820
tool_sandbox: "allow-scripts allow-same-origin"
tool_allow: "clipboard-write"
howto:
  - "Choisissez une couleur avec le sélecteur, ou tapez un code HEX à six chiffres comme `#00E5FF` dans le champ HEX."
  - "Les champs RGB et HSL ainsi que la barre d'aperçu se mettent à jour immédiatement."
  - "Cliquez sur le bouton de copie à côté de HEX, RGB ou HSL pour copier cette notation, prête pour le CSS."
  - "Cliquez sur **Générer Palette Néon** pour obtenir trois couleurs néon aléatoires issues de familles de teintes différentes."
  - "Cliquez sur une carte de la palette pour charger la couleur dans le convertisseur et la copier au format voulu."
faq:
  - q: "Comment convertir un code HEX en RGB ?"
    a: "Une couleur HEX, ce sont trois octets écrits en hexadécimal : `#RRVVBB`. Convertissez chaque paire en décimal : `#00E5FF` donne rouge 0x00 = 0, vert 0xE5 = 229, bleu 0xFF = 255, soit `rgb(0, 229, 255)`. La forme courte à trois chiffres comme `#0EF` double d'abord chaque chiffre (`#00EEFF`)."
  - q: "Qu'est-ce que le HSL et pourquoi l'utiliser ?"
    a: "Le HSL décrit une couleur par sa teinte (0–360° sur la roue chromatique), sa saturation (de 0 % gris à 100 % vif) et sa luminosité (de 0 % noir à 100 % blanc). Il est plus intuitif que le RVB : pour une version plus claire ou plus terne d'une couleur, on change un nombre au lieu de trois."
  - q: "Qu'est-ce qui donne à une couleur un aspect néon ?"
    a: "Une saturation très élevée et une luminosité moyenne sur fond sombre. Le générateur garde la saturation entre 85 % et 100 % et la luminosité entre 45 % et 60 %, la plage où les couleurs paraissent les plus lumineuses ; plus claires, elles tirent vers le pastel, plus sombres, elles perdent leur éclat."
  - q: "Les couleurs néon sont-elles accessibles ?"
    a: "Sur fond sombre, le cyan, le vert et le jaune néon passent généralement le contraste WCAG pour le grand texte, alors que les bleus, violets et magentas saturés échouent souvent. Utilisez le néon pour les accents, bordures et titres, gardez le texte courant presque blanc et vérifiez le contraste de chaque couple texte/fond."
  - q: "Puis-je saisir des valeurs RGB ou HSL ?"
    a: "Le convertisseur prend l'entrée du sélecteur et du champ HEX ; les champs RGB et HSL affichent le résultat à copier. Pour partir du RVB, convertissez-le en HEX ou réglez-le dans le sélecteur de couleur, qui accepte les valeurs RVB dans la plupart des navigateurs."
  - q: "Quelque chose est-il enregistré ou envoyé ?"
    a: "Non. Toutes les conversions sont de l'arithmétique en JavaScript dans cette page, et les palettes sont générées localement avec `Math.random()`."
---

## Comment ça marche

### Conversions

**HEX → RVB.** Les six chiffres hexadécimaux sont lus comme un seul entier de 24 bits, et les trois canaux extraits par décalage de bits : rouge = `(n >> 16) & 255`, vert = `(n >> 8) & 255`, bleu = `n & 255`.

**RVB → HSL.** Chaque canal est ramené entre 0 et 1. Avec *max* et *min* le plus grand et le plus petit des trois :

- **Luminosité** L = (max + min) / 2.
- **Saturation** S = 0 pour les gris ; sinon (max − min) / (max + min) si L ≤ 0,5, ou (max − min) / (2 − max − min) si L > 0,5.
- **Teinte** : dépend du canal le plus élevé : pour le rouge (V − B) / (max − min), pour le vert 2 + (B − R) / (max − min), pour le bleu 4 + (R − V) / (max − min), multipliée par 60° et ramenée entre 0 et 360°.

La teinte est arrondie au degré entier, S et L au pourcentage entier, la précision habituelle de `hsl()` en CSS.

| Couleur | HEX | RVB | HSL |
|---|---|---|---|
| Cyan néon | `#00E5FF` | 0, 229, 255 | 186°, 100 %, 50 % |
| Magenta vif | `#FF2DCE` | 255, 45, 206 | 314°, 100 %, 59 % |
| Vert acide | `#39FF14` | 57, 255, 20 | 111°, 100 %, 54 % |

### Le générateur néon

Le générateur connaît huit familles de teintes : cyan (170–195°), magenta (290–330°), bleu électrique (210–250°), vert néon (100–150°), rose vif (330–355°), violet (260–290°), orange néon (15–40°) et jaune néon (50–70°). À chaque clic, il les mélange, en prend trois et, pour chacune, tire une teinte aléatoire dans sa plage, une saturation de 85 à 100 % et une luminosité de 45 à 60 %. Les valeurs HSL sont converties en HEX avec la formule par morceaux standard : les trois couleurs viennent toujours de familles différentes mais partagent le même caractère vif et lumineux.

## Cas d'usage

- **CSS et design tokens.** Convertissez un HEX de marque en `rgb()` pour jouer sur l'opacité ou en `hsl()` pour construire des variantes plus claires et plus foncées.
- **Interfaces sombres et cyberpunk.** Générez des couleurs d'accent pour boutons, bordures, halos et graphiques sur fond sombre.
- **Affiches, miniatures et overlays de stream** au look synthwave ou enseigne au néon.
- **Thèmes de jeux et d'applis.** Choisissez trois accents néon complémentaires pour un HUD, un niveau ou un thème de terminal.
- **Comprendre les modèles de couleur.** Voyez comment HEX, RVB et HSL décrivent la même couleur, et comment la seule teinte fait tourner la roue.
