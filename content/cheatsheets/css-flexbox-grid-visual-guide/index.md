---
title: "CSS Layouts Cheatsheet: Flexbox & Grid Visual Guide"
description: "The definitive CSS Flexbox and Grid reference. Learn to center divs, build responsive layouts, master media queries, and use modern CSS variables with copy-paste examples."
date: 2026-02-11
tags: ["css", "cheatsheet", "frontend", "flexbox", "grid", "web-dev"]
keywords: ["css flexbox cheatsheet", "css grid tutorial", "center div css", "learn web dev", "responsive layout css", "media queries", "css variables", "frontend interview", "flexbox vs grid", "css layout guide", "css grid examples", "flexbox align items", "css gap property", "modern css 2026"]
draft: false
schema_json: >
  {
    "@context": "https://schema.org",
    "@type": "TechArticle",
    "name": "CSS Layouts Cheatsheet: Flexbox & Grid Visual Guide",
    "description": "Complete visual reference for CSS Flexbox and Grid layouts with responsive design patterns and modern CSS variables.",
    "proficiencyLevel": "Intermediate",
    "inLanguage": "en"
  }
---

## Rendering Engine Online

CSS layout is the skill that separates developers who build from developers who struggle. Flexbox handles one-dimensional flow — rows or columns. Grid handles two-dimensional layouts — rows AND columns simultaneously. Together, they replace every float hack, clearfix, and positioning trick from the past decade. This cheatsheet covers both systems with production-ready snippets, responsive patterns, and the modern CSS variables that keep your code maintainable. Every technique here is what frontend interviewers expect you to know. Copy, paste, ship.

---

## Flexbox Fundamentals

Flexbox works in one direction at a time — either a row or a column. The parent container controls the layout; children are the flex items.

### Container Properties

```css
.container {
  display: flex;            /* Activate flexbox */

  /* Direction: how items flow */
  flex-direction: row;             /* → left to right (default) */
  flex-direction: row-reverse;     /* ← right to left */
  flex-direction: column;          /* ↓ top to bottom */
  flex-direction: column-reverse;  /* ↑ bottom to top */

  /* Wrapping: what happens when items overflow */
  flex-wrap: nowrap;   /* Single line, items shrink (default) */
  flex-wrap: wrap;     /* Items wrap to next line */

  /* Main axis alignment (direction of flow) */
  justify-content: flex-start;     /* Pack at start |||....... */
  justify-content: flex-end;       /* Pack at end   .......|||*/
  justify-content: center;         /* Center        ...||| ...*/
  justify-content: space-between;  /* First & last at edges |..|..|*/
  justify-content: space-around;   /* Equal space around    .|..|..|.*/
  justify-content: space-evenly;   /* Equal space between   .|..|..|.*/

  /* Cross axis alignment (perpendicular to flow) */
  align-items: stretch;      /* Fill container height (default) */
  align-items: flex-start;   /* Align to top */
  align-items: flex-end;     /* Align to bottom */
  align-items: center;       /* Center vertically */
  align-items: baseline;     /* Align text baselines */

  /* Gap between items (modern replacement for margins) */
  gap: 20px;            /* Equal gap in both directions */
  gap: 20px 10px;       /* row-gap column-gap */
}
```

### Item Properties

```css
.item {
  /* Grow: how much extra space this item takes */
  flex-grow: 0;   /* Don't grow (default) */
  flex-grow: 1;   /* Take equal share of extra space */
  flex-grow: 2;   /* Take double share */

  /* Shrink: how much this item shrinks when space is tight */
  flex-shrink: 1;   /* Shrink equally (default) */
  flex-shrink: 0;   /* Never shrink (keep original size) */

  /* Basis: starting size before grow/shrink */
  flex-basis: auto;   /* Use content size (default) */
  flex-basis: 200px;  /* Start at 200px */
  flex-basis: 0;      /* Ignore content size, distribute all space */

  /* Shorthand: grow shrink basis */
  flex: 1;          /* flex: 1 1 0 — grow equally, ignore content */
  flex: 0 0 300px;  /* Fixed 300px, no grow, no shrink */
  flex: 1 0 200px;  /* Start at 200px, can grow, never shrink */

  /* Override cross-axis alignment for this item only */
  align-self: flex-start;
  align-self: center;
  align-self: flex-end;

  /* Reorder visually (does not change DOM order) */
  order: -1;  /* Move before default items */
  order: 0;   /* Default */
  order: 1;   /* Move after default items */
}
```

---

## Centering — The Eternal Question

Every method to center content in CSS, from simple to bulletproof.

```css
/* ✅ Method 1: Flexbox (most common) */
.center-flex {
  display: flex;
  justify-content: center;  /* horizontal */
  align-items: center;      /* vertical */
  min-height: 100vh;
}

/* ✅ Method 2: Grid (shortest) */
.center-grid {
  display: grid;
  place-items: center;      /* horizontal + vertical in one line */
  min-height: 100vh;
}

/* ✅ Method 3: Margin auto (block element) */
.center-margin {
  width: 300px;
  margin: 0 auto;           /* horizontal only */
}

/* ✅ Method 4: Absolute + Transform (legacy support) */
.center-absolute {
  position: absolute;
  top: 50%;
  left: 50%;
  transform: translate(-50%, -50%);
}

/* ✅ Method 5: Grid + margin auto (single child) */
.parent { display: grid; }
.child { margin: auto; }    /* centers in both axes */

/* ✅ Center text */
.center-text {
  text-align: center;            /* horizontal text */
  line-height: 100px;            /* vertical (single line, known height) */
}
```

---

## Common Flexbox Patterns

### Navbar

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

### Card Row (Responsive)

```css
.card-row {
  display: flex;
  flex-wrap: wrap;
  gap: 20px;
}
.card {
  flex: 1 1 300px;  /* grow, shrink, min 300px */
  max-width: 400px;
}
```

### Sticky Footer

```css
body {
  display: flex;
  flex-direction: column;
  min-height: 100vh;
}
main {
  flex: 1;  /* main grows to push footer down */
}
footer {
  flex-shrink: 0;
}
```

### Sidebar Layout

```css
.layout {
  display: flex;
  min-height: 100vh;
}
.sidebar {
  flex: 0 0 250px;  /* fixed 250px width */
}
.content {
  flex: 1;          /* takes remaining space */
}
```

---

## CSS Grid Fundamentals

Grid creates two-dimensional layouts. Define rows and columns, then place items into the grid cells.

### Container Properties

```css
.grid {
  display: grid;

  /* Define columns */
  grid-template-columns: 200px 1fr 200px;       /* fixed | flexible | fixed */
  grid-template-columns: repeat(3, 1fr);          /* 3 equal columns */
  grid-template-columns: repeat(auto-fill, minmax(250px, 1fr)); /* responsive */
  grid-template-columns: repeat(auto-fit, minmax(250px, 1fr));  /* responsive, stretch */

  /* Define rows */
  grid-template-rows: auto 1fr auto;       /* header | content | footer */
  grid-template-rows: repeat(3, 200px);    /* 3 rows, each 200px */

  /* Auto rows (for dynamic content) */
  grid-auto-rows: minmax(100px, auto);     /* at least 100px, grow as needed */

  /* Gap between cells */
  gap: 20px;            /* equal in both directions */
  gap: 20px 10px;       /* row-gap column-gap */

  /* Alignment of ALL items within their cells */
  justify-items: start | center | end | stretch;
  align-items: start | center | end | stretch;

  /* Alignment of the GRID within the container */
  justify-content: start | center | end | space-between | space-around;
  align-content: start | center | end | space-between | space-around;

  /* Shorthand: align + justify */
  place-items: center;         /* both axes */
  place-content: center;       /* both axes */
}
```

### auto-fill vs auto-fit

```css
/* auto-fill: create as many columns as fit, leave empty columns */
grid-template-columns: repeat(auto-fill, minmax(200px, 1fr));
/* With 3 items in a 1000px container: creates 5 tracks, 2 empty */

/* auto-fit: same as auto-fill, but collapses empty tracks */
grid-template-columns: repeat(auto-fit, minmax(200px, 1fr));
/* With 3 items in a 1000px container: items stretch to fill */
```

### Item Placement

```css
.item {
  /* Span specific columns */
  grid-column: 1 / 3;        /* start at line 1, end at line 3 (span 2) */
  grid-column: 1 / -1;       /* span ALL columns (full width) */
  grid-column: span 2;       /* span 2 columns from current position */

  /* Span specific rows */
  grid-row: 1 / 3;           /* start at line 1, end at line 3 */
  grid-row: span 3;          /* span 3 rows */

  /* Place at exact cell */
  grid-column: 2;
  grid-row: 1;

  /* Shorthand: row-start / col-start / row-end / col-end */
  grid-area: 1 / 1 / 3 / 3;  /* top-left 2x2 block */

  /* Override alignment for this item */
  justify-self: center;
  align-self: end;
}
```

---

## Grid Template Areas

Name your layout regions for readable, visual grid definitions.

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

/* Responsive: stack on mobile */
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

## Common Grid Patterns

### Responsive Card Grid

```css
.card-grid {
  display: grid;
  grid-template-columns: repeat(auto-fit, minmax(280px, 1fr));
  gap: 24px;
  padding: 24px;
}
/* Cards automatically wrap to new rows as the viewport shrinks */
```

### Dashboard Layout

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

### Image Gallery (Masonry-like)

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

### Holy Grail Layout

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

Respond to viewport size, user preferences, and device features.

```css
/* Mobile-first approach (recommended) */
/* Base styles = mobile */
.container { padding: 16px; }

/* Tablet and up */
@media (min-width: 768px) {
  .container { padding: 24px; max-width: 720px; margin: 0 auto; }
}

/* Desktop and up */
@media (min-width: 1024px) {
  .container { max-width: 960px; }
}

/* Large desktop */
@media (min-width: 1280px) {
  .container { max-width: 1200px; }
}

/* Common breakpoints */
/* 480px  — small phones */
/* 768px  — tablets */
/* 1024px — small desktops */
/* 1280px — large desktops */
/* 1536px — extra large */

/* Dark mode detection */
@media (prefers-color-scheme: dark) {
  :root {
    --bg: #0a0a0a;
    --text: #e0e0e0;
  }
}

/* Reduced motion (accessibility) */
@media (prefers-reduced-motion: reduce) {
  * {
    animation-duration: 0.01ms !important;
    transition-duration: 0.01ms !important;
  }
}

/* Hover capability (touch vs mouse) */
@media (hover: hover) {
  .card:hover { transform: translateY(-4px); }
}

/* Print styles */
@media print {
  .no-print { display: none; }
  body { font-size: 12pt; color: #000; }
}

/* Container queries (modern CSS) */
.card-container {
  container-type: inline-size;
}
@container (min-width: 400px) {
  .card { flex-direction: row; }
}
```

---

## CSS Custom Properties (Variables)

Define reusable values that can be overridden per context. The foundation of themeable design systems.

```css
/* Define on :root for global access */
:root {
  /* Colors */
  --color-primary: #00e5ff;
  --color-secondary: #7b1fa2;
  --color-bg: #0a0a0a;
  --color-surface: #1a1a2e;
  --color-text: #e0e0e0;
  --color-text-muted: #888;
  --color-success: #00ff41;
  --color-error: #ff3d3d;

  /* Typography */
  --font-body: "Inter", -apple-system, sans-serif;
  --font-mono: "Fira Code", "Courier New", monospace;
  --font-size-sm: 0.875rem;
  --font-size-md: 1rem;
  --font-size-lg: 1.25rem;
  --font-size-xl: 2rem;

  /* Spacing scale */
  --space-xs: 4px;
  --space-sm: 8px;
  --space-md: 16px;
  --space-lg: 24px;
  --space-xl: 48px;

  /* Borders & Shadows */
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

/* Usage */
.card {
  background: var(--color-surface);
  color: var(--color-text);
  padding: var(--space-lg);
  border-radius: var(--radius-md);
  box-shadow: var(--shadow-md);
  font-family: var(--font-body);
  transition: transform var(--transition-normal);
}

/* Fallback values */
.element {
  color: var(--color-accent, #ff6600); /* uses #ff6600 if --color-accent undefined */
}

/* Override in context (theming) */
[data-theme="light"] {
  --color-bg: #ffffff;
  --color-surface: #f5f5f5;
  --color-text: #1a1a1a;
}

/* Override in component */
.card-danger {
  --color-primary: var(--color-error);
}

/* Dynamic values with calc() */
.responsive-padding {
  padding: calc(var(--space-md) + 1vw);
}

/* Variables in media queries */
@media (max-width: 768px) {
  :root {
    --font-size-xl: 1.5rem;
    --space-lg: 16px;
  }
}
```

---

## Modern CSS Features

```css
/* aspect-ratio — maintain proportions */
.video-container {
  aspect-ratio: 16 / 9;
  width: 100%;
}
.avatar {
  aspect-ratio: 1;       /* perfect square */
  border-radius: 50%;
}

/* clamp() — responsive values without media queries */
.title {
  font-size: clamp(1.5rem, 4vw, 3rem);  /* min, preferred, max */
}
.container {
  width: clamp(300px, 90%, 1200px);
}
.card {
  padding: clamp(16px, 3vw, 48px);
}

/* min() and max() */
.sidebar {
  width: min(300px, 30%);   /* whichever is smaller */
}
.hero {
  height: max(400px, 50vh); /* whichever is larger */
}

/* :is() and :where() — reduce selector repetition */
/* Before: */
.card h1, .card h2, .card h3 { color: white; }
/* After: */
.card :is(h1, h2, h3) { color: white; }

/* :has() — parent selector (game changer) */
.card:has(img) { padding: 0; }                     /* card that contains an image */
.form:has(:invalid) .submit { opacity: 0.5; }      /* form with invalid inputs */
.nav:has(.dropdown:hover) { background: #111; }    /* nav when dropdown is hovered */

/* Logical properties (RTL support) */
.element {
  margin-inline-start: 20px;   /* left in LTR, right in RTL */
  padding-block: 10px;          /* top + bottom */
  border-inline-end: 1px solid; /* right in LTR, left in RTL */
}

/* scroll-snap — smooth scroll snapping */
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

/* accent-color — style native form controls */
input[type="checkbox"],
input[type="radio"],
input[type="range"] {
  accent-color: var(--color-primary);
}
```

---

## Flexbox vs Grid — When to Use Which

| Scenario | Use | Why |
|---|---|---|
| Navbar | Flexbox | One-dimensional row with spacing |
| Card grid | Grid | Two-dimensional, equal-height rows |
| Form layout | Grid | Aligned labels and inputs in columns |
| Centering one element | Grid | `place-items: center` is the shortest |
| Sidebar + content | Grid or Flexbox | Grid for template areas, Flex for simple split |
| Responsive card list | Grid | `auto-fit` + `minmax` handles everything |
| Space between items | Flexbox | `justify-content: space-between` |
| Dashboard widgets | Grid | Span multiple rows/columns |
| Vertically stacked sections | Flexbox | Column direction with `gap` |
| Complex page layout | Grid | Template areas for named regions |

**Rule of thumb**: Flexbox for components (navbars, buttons, small layouts). Grid for page-level layouts and anything that needs rows AND columns.

---

## Reset & Base Styles

A minimal reset for consistent cross-browser rendering.

```css
/* Modern CSS Reset */
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

/* Accessibility: respect user preferences */
@media (prefers-reduced-motion: reduce) {
  html { scroll-behavior: auto; }
}
```

---

## Quick Reference

| Property | Flexbox | Grid |
|---|---|---|
| Activate | `display: flex` | `display: grid` |
| Direction | `flex-direction` | `grid-template-columns/rows` |
| Wrap | `flex-wrap: wrap` | Automatic with `auto-fit` |
| Gap | `gap` | `gap` |
| Horizontal align | `justify-content` | `justify-items` / `justify-content` |
| Vertical align | `align-items` | `align-items` / `align-content` |
| Item sizing | `flex: 1 0 200px` | `minmax(200px, 1fr)` |
| Center everything | `justify-content + align-items: center` | `place-items: center` |
| Responsive | `flex-wrap` + media queries | `auto-fit` + `minmax()` |

---

## End of Transmission

This cheatsheet covers the CSS layout techniques that power every modern website — from centering a div to building complex responsive dashboards. Flexbox for one-dimensional flow, Grid for two-dimensional layouts, and CSS variables for maintainable design systems. Bookmark it, reference it in frontend interviews, and stop fighting with CSS. The layout engine works for you now.
