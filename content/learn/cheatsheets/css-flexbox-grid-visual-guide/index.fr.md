---
title: "Cheatsheet Layouts CSS : Guide Visuel Flexbox & Grid"
description: "La référence définitive CSS Flexbox et Grid. Apprenez à centrer des divs, construire des layouts responsive, maîtriser les media queries et utiliser les variables CSS modernes avec des exemples prêts à copier-coller."
date: 2026-02-10
tags: ["css", "cheatsheet", "frontend", "flexbox", "grid", "web-dev"]
keywords: ["css flexbox cheatsheet", "css grid tutoriel", "centrer div css", "apprendre web dev", "layout responsive css", "media queries", "variables css", "entretien frontend", "flexbox vs grid", "guide layout css", "exemples css grid", "flexbox align items", "propriété gap css", "css moderne 2026"]
draft: false
schema_json: >
  {
    "@context": "https://schema.org",
    "@type": "TechArticle",
    "name": "Cheatsheet Layouts CSS : Guide Visuel Flexbox & Grid",
    "description": "Référence visuelle complète pour les layouts CSS Flexbox et Grid avec des patterns de design responsive et des variables CSS modernes.",
    "proficiencyLevel": "Intermediate",
    "inLanguage": "fr"
  }
---

## Moteur de Rendu en Ligne

Le layout CSS est la compétence qui sépare les développeurs qui construisent de ceux qui galèrent. Flexbox gère le flux unidimensionnel — lignes ou colonnes. Grid gère les layouts bidimensionnels — lignes ET colonnes simultanément. Ensemble, ils remplacent chaque hack avec float, clearfix et astuce de positionnement de la dernière décennie. Cette cheatsheet couvre les deux systèmes avec des extraits prêts pour la production, des patterns responsive et les variables CSS modernes qui gardent votre code maintenable. Chaque technique ici est ce que les recruteurs frontend attendent que vous sachiez. Copiez, collez, déployez.

---

## Fondamentaux de Flexbox

Flexbox fonctionne dans une direction à la fois — soit une ligne, soit une colonne. Le conteneur parent contrôle la mise en page ; les enfants sont les éléments flex.

### Propriétés du Conteneur

```css
.container {
  display: flex;            /* Activer flexbox */

  /* Direction : comment les éléments s'écoulent */
  flex-direction: row;             /* → de gauche à droite (par défaut) */
  flex-direction: row-reverse;     /* ← de droite à gauche */
  flex-direction: column;          /* ↓ de haut en bas */
  flex-direction: column-reverse;  /* ↑ de bas en haut */

  /* Retour à la ligne : que se passe-t-il quand les éléments débordent */
  flex-wrap: nowrap;   /* Ligne unique, les éléments rétrécissent (par défaut) */
  flex-wrap: wrap;     /* Les éléments passent à la ligne suivante */

  /* Alignement de l'axe principal (direction du flux) */
  justify-content: flex-start;     /* Grouper au début |||....... */
  justify-content: flex-end;       /* Grouper à la fin .......|||*/
  justify-content: center;         /* Centrer          ...||| ...*/
  justify-content: space-between;  /* Premier et dernier aux bords |..|..|*/
  justify-content: space-around;   /* Espace égal autour          .|..|..|.*/
  justify-content: space-evenly;   /* Espace égal entre           .|..|..|.*/

  /* Alignement de l'axe transversal (perpendiculaire au flux) */
  align-items: stretch;      /* Remplir la hauteur du conteneur (par défaut) */
  align-items: flex-start;   /* Aligner en haut */
  align-items: flex-end;     /* Aligner en bas */
  align-items: center;       /* Centrer verticalement */
  align-items: baseline;     /* Aligner les lignes de base du texte */

  /* Espacement entre éléments (remplacement moderne des marges) */
  gap: 20px;            /* Espace égal dans les deux directions */
  gap: 20px 10px;       /* gap-ligne gap-colonne */
}
```

### Propriétés des Éléments

```css
.item {
  /* Croissance : combien d'espace supplémentaire cet élément prend */
  flex-grow: 0;   /* Ne pas grandir (par défaut) */
  flex-grow: 1;   /* Prendre une part égale de l'espace supplémentaire */
  flex-grow: 2;   /* Prendre le double */

  /* Rétrécissement : combien cet élément rétrécit quand l'espace est limité */
  flex-shrink: 1;   /* Rétrécir également (par défaut) */
  flex-shrink: 0;   /* Ne jamais rétrécir (garder la taille originale) */

  /* Base : taille de départ avant croissance/rétrécissement */
  flex-basis: auto;   /* Utiliser la taille du contenu (par défaut) */
  flex-basis: 200px;  /* Commencer à 200px */
  flex-basis: 0;      /* Ignorer la taille du contenu, distribuer tout l'espace */

  /* Raccourci : croissance rétrécissement base */
  flex: 1;          /* flex: 1 1 0 — grandir également, ignorer le contenu */
  flex: 0 0 300px;  /* Fixe 300px, pas de croissance, pas de rétrécissement */
  flex: 1 0 200px;  /* Commencer à 200px, peut grandir, ne rétrécit jamais */

  /* Remplacer l'alignement de l'axe transversal pour cet élément uniquement */
  align-self: flex-start;
  align-self: center;
  align-self: flex-end;

  /* Réordonner visuellement (ne change pas l'ordre du DOM) */
  order: -1;  /* Déplacer avant les éléments par défaut */
  order: 0;   /* Par défaut */
  order: 1;   /* Déplacer après les éléments par défaut */
}
```

---

## Centrage — L'Éternelle Question

Toutes les méthodes pour centrer du contenu en CSS, du simple au blindé.

```css
/* ✅ Méthode 1 : Flexbox (la plus courante) */
.center-flex {
  display: flex;
  justify-content: center;  /* horizontal */
  align-items: center;      /* vertical */
  min-height: 100vh;
}

/* ✅ Méthode 2 : Grid (la plus courte) */
.center-grid {
  display: grid;
  place-items: center;      /* horizontal + vertical en une ligne */
  min-height: 100vh;
}

/* ✅ Méthode 3 : Marge auto (élément bloc) */
.center-margin {
  width: 300px;
  margin: 0 auto;           /* horizontal uniquement */
}

/* ✅ Méthode 4 : Absolu + Transform (support legacy) */
.center-absolute {
  position: absolute;
  top: 50%;
  left: 50%;
  transform: translate(-50%, -50%);
}

/* ✅ Méthode 5 : Grid + marge auto (enfant unique) */
.parent { display: grid; }
.child { margin: auto; }    /* centre sur les deux axes */

/* ✅ Centrer le texte */
.center-text {
  text-align: center;            /* texte horizontal */
  line-height: 100px;            /* vertical (ligne unique, hauteur connue) */
}
```

---

## Patterns Flexbox Courants

### Barre de Navigation

```css
.navbar {
  display: flex;
  justify-content: space-between;
  align-items: center;
  padding: 0 20px;
  height: 60px;
}
.navbar .logo { flex-shrink: 0; }
.navbar .nav-links {
  display: flex;
  gap: 20px;
  list-style: none;
}
```

### Rangée de Cards (Responsive)

```css
.card-row {
  display: flex;
  flex-wrap: wrap;
  gap: 20px;
}
.card {
  flex: 1 1 300px;  /* grandir, rétrécir, minimum 300px */
  max-width: 400px;
}
```

### Footer Fixe

```css
body {
  display: flex;
  flex-direction: column;
  min-height: 100vh;
}
main {
  flex: 1;  /* le main grandit pour pousser le footer vers le bas */
}
footer {
  flex-shrink: 0;
}
```

### Layout avec Sidebar

```css
.layout {
  display: flex;
  min-height: 100vh;
}
.sidebar {
  flex: 0 0 250px;  /* largeur fixe de 250px */
}
.content {
  flex: 1;          /* prend l'espace restant */
}
```

---

## Fondamentaux de CSS Grid

Grid crée des layouts bidimensionnels. Définissez des lignes et des colonnes, puis placez des éléments dans les cellules de la grille.

### Propriétés du Conteneur

```css
.grid {
  display: grid;

  /* Définir les colonnes */
  grid-template-columns: 200px 1fr 200px;       /* fixe | flexible | fixe */
  grid-template-columns: repeat(3, 1fr);          /* 3 colonnes égales */
  grid-template-columns: repeat(auto-fill, minmax(250px, 1fr)); /* responsive */
  grid-template-columns: repeat(auto-fit, minmax(250px, 1fr));  /* responsive, s'étire */

  /* Définir les lignes */
  grid-template-rows: auto 1fr auto;       /* header | contenu | footer */
  grid-template-rows: repeat(3, 200px);    /* 3 lignes, chacune 200px */

  /* Lignes automatiques (pour contenu dynamique) */
  grid-auto-rows: minmax(100px, auto);     /* au moins 100px, grandit selon les besoins */

  /* Espacement entre les cellules */
  gap: 20px;            /* égal dans les deux directions */
  gap: 20px 10px;       /* gap-ligne gap-colonne */

  /* Alignement de TOUS les éléments dans leurs cellules */
  justify-items: start | center | end | stretch;
  align-items: start | center | end | stretch;

  /* Alignement de la GRILLE dans le conteneur */
  justify-content: start | center | end | space-between | space-around;
  align-content: start | center | end | space-between | space-around;

  /* Raccourci : aligner + justifier */
  place-items: center;         /* les deux axes */
  place-content: center;       /* les deux axes */
}
```

### auto-fill vs auto-fit

```css
/* auto-fill : crée autant de colonnes que possible, laisse les colonnes vides */
grid-template-columns: repeat(auto-fill, minmax(200px, 1fr));
/* Avec 3 éléments dans un conteneur de 1000px : crée 5 pistes, 2 vides */

/* auto-fit : comme auto-fill, mais compresse les pistes vides */
grid-template-columns: repeat(auto-fit, minmax(200px, 1fr));
/* Avec 3 éléments dans un conteneur de 1000px : les éléments s'étirent pour remplir */
```

### Placement des Éléments

```css
.item {
  /* S'étendre sur des colonnes spécifiques */
  grid-column: 1 / 3;        /* commence à la ligne 1, finit à la ligne 3 (couvre 2) */
  grid-column: 1 / -1;       /* couvrir TOUTES les colonnes (pleine largeur) */
  grid-column: span 2;       /* couvrir 2 colonnes depuis la position actuelle */

  /* S'étendre sur des lignes spécifiques */
  grid-row: 1 / 3;           /* commence à la ligne 1, finit à la ligne 3 */
  grid-row: span 3;          /* couvrir 3 lignes */

  /* Placer dans une cellule exacte */
  grid-column: 2;
  grid-row: 1;

  /* Raccourci : début-ligne / début-col / fin-ligne / fin-col */
  grid-area: 1 / 1 / 3 / 3;  /* bloc 2x2 en haut à gauche */

  /* Remplacer l'alignement pour cet élément */
  justify-self: center;
  align-self: end;
}
```

---

## Zones de Modèle Grid

Nommez les régions de votre layout pour des définitions de grille lisibles et visuelles.

```css
.layout {
  display: grid;
  grid-template-areas:
    "header  header  header"
    "sidebar content content"
    "footer  footer  footer";
  grid-template-columns: 250px 1fr 1fr;
  grid-template-rows: 60px 1fr 50px;
  min-height: 100vh;
  gap: 0;
}

.header  { grid-area: header; }
.sidebar { grid-area: sidebar; }
.content { grid-area: content; }
.footer  { grid-area: footer; }

/* Responsive : empiler sur mobile */
@media (max-width: 768px) {
  .layout {
    grid-template-areas:
      "header"
      "content"
      "sidebar"
      "footer";
    grid-template-columns: 1fr;
    grid-template-rows: auto;
  }
}
```

---

## Patterns Grid Courants

### Grille de Cards Responsive

```css
.card-grid {
  display: grid;
  grid-template-columns: repeat(auto-fit, minmax(280px, 1fr));
  gap: 24px;
  padding: 24px;
}
/* Les cards passent automatiquement à de nouvelles lignes quand la viewport rétrécit */
```

### Layout Dashboard

```css
.dashboard {
  display: grid;
  grid-template-columns: repeat(4, 1fr);
  grid-auto-rows: minmax(150px, auto);
  gap: 16px;
}
.widget-large {
  grid-column: span 2;
  grid-row: span 2;
}
.widget-wide {
  grid-column: span 2;
}
```

### Galerie d'Images (Style Masonry)

```css
.gallery {
  display: grid;
  grid-template-columns: repeat(auto-fill, minmax(200px, 1fr));
  grid-auto-rows: 200px;
  gap: 10px;
}
.gallery .featured {
  grid-column: span 2;
  grid-row: span 2;
}
.gallery img {
  width: 100%;
  height: 100%;
  object-fit: cover;
  border-radius: 8px;
}
```

### Layout Holy Grail

```css
.holy-grail {
  display: grid;
  grid-template:
    "header header header" 60px
    "nav    main   aside"  1fr
    "footer footer footer" 50px
    / 200px 1fr    200px;
  min-height: 100vh;
}
```

---

## Media Queries

Répondez à la taille de la viewport, aux préférences de l'utilisateur et aux caractéristiques de l'appareil.

```css
/* Approche mobile-first (recommandée) */
/* Styles de base = mobile */
.container { padding: 16px; }

/* Tablette et plus */
@media (min-width: 768px) {
  .container { padding: 24px; max-width: 720px; margin: 0 auto; }
}

/* Bureau et plus */
@media (min-width: 1024px) {
  .container { max-width: 960px; }
}

/* Grand bureau */
@media (min-width: 1280px) {
  .container { max-width: 1200px; }
}

/* Points de rupture courants */
/* 480px  — petits téléphones */
/* 768px  — tablettes */
/* 1024px — petits bureaux */
/* 1280px — grands bureaux */
/* 1536px — très grands */

/* Détection du mode sombre */
@media (prefers-color-scheme: dark) {
  :root {
    --bg: #0a0a0a;
    --text: #e0e0e0;
  }
}

/* Mouvement réduit (accessibilité) */
@media (prefers-reduced-motion: reduce) {
  * {
    animation-duration: 0.01ms !important;
    transition-duration: 0.01ms !important;
  }
}

/* Capacité de survol (tactile vs souris) */
@media (hover: hover) {
  .card:hover { transform: translateY(-4px); }
}

/* Styles d'impression */
@media print {
  .no-print { display: none; }
  body { font-size: 12pt; color: #000; }
}

/* Requêtes de conteneur (CSS moderne) */
.card-container {
  container-type: inline-size;
}
@container (min-width: 400px) {
  .card { flex-direction: row; }
}
```

---

## Propriétés Personnalisées CSS (Variables)

Définissez des valeurs réutilisables qui peuvent être remplacées par contexte. La base des systèmes de design thématisables.

```css
/* Définir sur :root pour un accès global */
:root {
  /* Couleurs */
  --color-primary: #00e5ff;
  --color-secondary: #7b1fa2;
  --color-bg: #0a0a0a;
  --color-surface: #1a1a2e;
  --color-text: #e0e0e0;
  --color-text-muted: #888;
  --color-success: #00ff41;
  --color-error: #ff3d3d;

  /* Typographie */
  --font-body: "Inter", -apple-system, sans-serif;
  --font-mono: "Fira Code", "Courier New", monospace;
  --font-size-sm: 0.875rem;
  --font-size-md: 1rem;
  --font-size-lg: 1.25rem;
  --font-size-xl: 2rem;

  /* Échelle d'espacement */
  --space-xs: 4px;
  --space-sm: 8px;
  --space-md: 16px;
  --space-lg: 24px;
  --space-xl: 48px;

  /* Bordures et Ombres */
  --radius-sm: 4px;
  --radius-md: 8px;
  --radius-lg: 16px;
  --shadow-sm: 0 1px 3px rgba(0, 0, 0, 0.2);
  --shadow-md: 0 4px 12px rgba(0, 0, 0, 0.3);
  --shadow-lg: 0 10px 30px rgba(0, 0, 0, 0.5);

  /* Transitions */
  --transition-fast: 150ms ease;
  --transition-normal: 300ms ease;
}

/* Utilisation */
.card {
  background: var(--color-surface);
  color: var(--color-text);
  padding: var(--space-lg);
  border-radius: var(--radius-md);
  box-shadow: var(--shadow-md);
  font-family: var(--font-body);
  transition: transform var(--transition-normal);
}

/* Valeurs de repli */
.element {
  color: var(--color-accent, #ff6600); /* utilise #ff6600 si --color-accent n'est pas défini */
}

/* Remplacement dans le contexte (thématisation) */
[data-theme="light"] {
  --color-bg: #ffffff;
  --color-surface: #f5f5f5;
  --color-text: #1a1a1a;
}

/* Remplacement dans le composant */
.card-danger {
  --color-primary: var(--color-error);
}

/* Valeurs dynamiques avec calc() */
.responsive-padding {
  padding: calc(var(--space-md) + 1vw);
}

/* Variables dans les media queries */
@media (max-width: 768px) {
  :root {
    --font-size-xl: 1.5rem;
    --space-lg: 16px;
  }
}
```

---

## Fonctionnalités CSS Modernes

```css
/* aspect-ratio — maintenir les proportions */
.video-container {
  aspect-ratio: 16 / 9;
  width: 100%;
}
.avatar {
  aspect-ratio: 1;       /* carré parfait */
  border-radius: 50%;
}

/* clamp() — valeurs responsive sans media queries */
.title {
  font-size: clamp(1.5rem, 4vw, 3rem);  /* min, préféré, max */
}
.container {
  width: clamp(300px, 90%, 1200px);
}
.card {
  padding: clamp(16px, 3vw, 48px);
}

/* min() et max() */
.sidebar {
  width: min(300px, 30%);   /* le plus petit des deux */
}
.hero {
  height: max(400px, 50vh); /* le plus grand des deux */
}

/* :is() et :where() — réduire la répétition des sélecteurs */
/* Avant : */
.card h1, .card h2, .card h3 { color: white; }
/* Après : */
.card :is(h1, h2, h3) { color: white; }

/* :has() — sélecteur parent (révolutionnaire) */
.card:has(img) { padding: 0; }                     /* card contenant une image */
.form:has(:invalid) .submit { opacity: 0.5; }      /* formulaire avec des inputs invalides */
.nav:has(.dropdown:hover) { background: #111; }    /* nav quand le dropdown est survolé */

/* Propriétés logiques (support RTL) */
.element {
  margin-inline-start: 20px;   /* gauche en LTR, droite en RTL */
  padding-block: 10px;          /* haut + bas */
  border-inline-end: 1px solid; /* droite en LTR, gauche en RTL */
}

/* scroll-snap — défilement fluide avec accrochage */
.carousel {
  display: flex;
  overflow-x: auto;
  scroll-snap-type: x mandatory;
  gap: 16px;
}
.carousel > * {
  scroll-snap-align: start;
  flex: 0 0 300px;
}

/* accent-color — personnaliser les contrôles natifs de formulaire */
input[type="checkbox"],
input[type="radio"],
input[type="range"] {
  accent-color: var(--color-primary);
}
```

---

## Flexbox vs Grid — Quand Utiliser Lequel

| Scénario | Utiliser | Pourquoi |
|---|---|---|
| Barre de navigation | Flexbox | Ligne unidimensionnelle avec espacement |
| Grille de cards | Grid | Bidimensionnel, lignes de hauteur égale |
| Layout de formulaire | Grid | Labels et inputs alignés en colonnes |
| Centrer un élément | Grid | `place-items: center` est le plus court |
| Sidebar + contenu | Grid ou Flexbox | Grid pour les zones de modèle, Flex pour une division simple |
| Liste de cards responsive | Grid | `auto-fit` + `minmax` gère tout |
| Espace entre éléments | Flexbox | `justify-content: space-between` |
| Widgets de dashboard | Grid | Couvrir plusieurs lignes/colonnes |
| Sections empilées verticalement | Flexbox | Direction colonne avec `gap` |
| Layout de page complexe | Grid | Zones de modèle pour des régions nommées |

**Règle d'or** : Flexbox pour les composants (barres de navigation, boutons, petits layouts). Grid pour les layouts au niveau de la page et tout ce qui nécessite des lignes ET des colonnes.

---

## Reset et Styles de Base

Un reset minimal pour un rendu cohérent entre les navigateurs.

```css
/* Reset CSS Moderne */
*,
*::before,
*::after {
  box-sizing: border-box;
  margin: 0;
  padding: 0;
}

html {
  font-size: 16px;
  -webkit-text-size-adjust: 100%;
  scroll-behavior: smooth;
}

body {
  font-family: var(--font-body);
  line-height: 1.6;
  color: var(--color-text);
  background: var(--color-bg);
  -webkit-font-smoothing: antialiased;
}

img, video, svg {
  display: block;
  max-width: 100%;
  height: auto;
}

a {
  color: inherit;
  text-decoration: none;
}

button {
  font: inherit;
  cursor: pointer;
  border: none;
  background: none;
}

ul, ol { list-style: none; }

/* Accessibilité : respecter les préférences de l'utilisateur */
@media (prefers-reduced-motion: reduce) {
  html { scroll-behavior: auto; }
}
```

---

## Référence Rapide

| Propriété | Flexbox | Grid |
|---|---|---|
| Activer | `display: flex` | `display: grid` |
| Direction | `flex-direction` | `grid-template-columns/rows` |
| Retour à la ligne | `flex-wrap: wrap` | Automatique avec `auto-fit` |
| Espacement | `gap` | `gap` |
| Alignement horizontal | `justify-content` | `justify-items` / `justify-content` |
| Alignement vertical | `align-items` | `align-items` / `align-content` |
| Dimensionnement des éléments | `flex: 1 0 200px` | `minmax(200px, 1fr)` |
| Tout centrer | `justify-content + align-items: center` | `place-items: center` |
| Responsive | `flex-wrap` + media queries | `auto-fit` + `minmax()` |

---

## Fin de Transmission

Cette cheatsheet couvre les techniques de layout CSS qui alimentent chaque site web moderne — du centrage d'un div à la construction de dashboards responsive complexes. Flexbox pour le flux unidimensionnel, Grid pour les layouts bidimensionnels et les variables CSS pour des systèmes de design maintenables. Mettez-la en favori, consultez-la lors des entretiens frontend et arrêtez de vous battre avec le CSS. Le moteur de layout travaille pour vous maintenant.
