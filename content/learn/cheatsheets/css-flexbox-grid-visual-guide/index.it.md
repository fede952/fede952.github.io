---
title: "Cheatsheet Layout CSS: Guida Visiva Flexbox & Grid"
description: "Il riferimento definitivo per CSS Flexbox e Grid. Impara a centrare i div, costruire layout responsive, padroneggiare le media query e usare le variabili CSS moderne con esempi da copiare e incollare."
date: 2026-02-10
tags: ["css", "cheatsheet", "frontend", "flexbox", "grid", "web-dev"]
keywords: ["css flexbox cheatsheet", "css grid tutorial", "centrare div css", "imparare web dev", "layout responsive css", "media queries", "variabili css", "colloquio frontend", "flexbox vs grid", "guida layout css", "esempi css grid", "flexbox align items", "proprietà gap css", "css moderno 2026"]
draft: false
schema_json: >
  {
    "@context": "https://schema.org",
    "@type": "TechArticle",
    "name": "Cheatsheet Layout CSS: Guida Visiva Flexbox & Grid",
    "description": "Riferimento visivo completo per i layout CSS Flexbox e Grid con pattern di design responsive e variabili CSS moderne.",
    "proficiencyLevel": "Intermediate",
    "inLanguage": "it"
  }
---

## Motore di Rendering Online

Il layout CSS è la competenza che separa gli sviluppatori che costruiscono da quelli che faticano. Flexbox gestisce il flusso unidimensionale — righe o colonne. Grid gestisce i layout bidimensionali — righe E colonne simultaneamente. Insieme, sostituiscono ogni hack con float, clearfix e trucco di posizionamento dell'ultimo decennio. Questa cheatsheet copre entrambi i sistemi con snippet pronti per la produzione, pattern responsive e le variabili CSS moderne che mantengono il tuo codice manutenibile. Ogni tecnica qui è ciò che gli intervistatori frontend si aspettano che tu sappia. Copia, incolla, pubblica.

---

## Fondamenti di Flexbox

Flexbox funziona in una direzione alla volta — o una riga o una colonna. Il contenitore padre controlla il layout; i figli sono gli elementi flex.

### Proprietà del Contenitore

```css
.container {
  display: flex;            /* Attiva flexbox */

  /* Direzione: come scorrono gli elementi */
  flex-direction: row;             /* → da sinistra a destra (predefinito) */
  flex-direction: row-reverse;     /* ← da destra a sinistra */
  flex-direction: column;          /* ↓ dall'alto al basso */
  flex-direction: column-reverse;  /* ↑ dal basso all'alto */

  /* A capo: cosa succede quando gli elementi traboccano */
  flex-wrap: nowrap;   /* Linea singola, gli elementi si restringono (predefinito) */
  flex-wrap: wrap;     /* Gli elementi vanno a capo sulla riga successiva */

  /* Allineamento asse principale (direzione del flusso) */
  justify-content: flex-start;     /* Impacchetta all'inizio |||....... */
  justify-content: flex-end;       /* Impacchetta alla fine  .......|||*/
  justify-content: center;         /* Centra               ...||| ...*/
  justify-content: space-between;  /* Primo e ultimo ai bordi |..|..|*/
  justify-content: space-around;   /* Spazio uguale intorno   .|..|..|.*/
  justify-content: space-evenly;   /* Spazio uguale tra       .|..|..|.*/

  /* Allineamento asse trasversale (perpendicolare al flusso) */
  align-items: stretch;      /* Riempi l'altezza del contenitore (predefinito) */
  align-items: flex-start;   /* Allinea in alto */
  align-items: flex-end;     /* Allinea in basso */
  align-items: center;       /* Centra verticalmente */
  align-items: baseline;     /* Allinea le linee di base del testo */

  /* Spazio tra gli elementi (sostituto moderno dei margini) */
  gap: 20px;            /* Spazio uguale in entrambe le direzioni */
  gap: 20px 10px;       /* gap-riga gap-colonna */
}
```

### Proprietà degli Elementi

```css
.item {
  /* Crescita: quanto spazio extra prende questo elemento */
  flex-grow: 0;   /* Non crescere (predefinito) */
  flex-grow: 1;   /* Prendi una quota uguale dello spazio extra */
  flex-grow: 2;   /* Prendi il doppio della quota */

  /* Restringimento: quanto si restringe questo elemento quando lo spazio è limitato */
  flex-shrink: 1;   /* Restringi ugualmente (predefinito) */
  flex-shrink: 0;   /* Non restringere mai (mantieni la dimensione originale) */

  /* Base: dimensione iniziale prima di crescita/restringimento */
  flex-basis: auto;   /* Usa la dimensione del contenuto (predefinito) */
  flex-basis: 200px;  /* Inizia a 200px */
  flex-basis: 0;      /* Ignora la dimensione del contenuto, distribuisci tutto lo spazio */

  /* Abbreviazione: crescita restringimento base */
  flex: 1;          /* flex: 1 1 0 — cresci ugualmente, ignora il contenuto */
  flex: 0 0 300px;  /* Fisso 300px, non crescere, non restringere */
  flex: 1 0 200px;  /* Inizia a 200px, può crescere, non si restringe mai */

  /* Sovrascrivi l'allineamento dell'asse trasversale solo per questo elemento */
  align-self: flex-start;
  align-self: center;
  align-self: flex-end;

  /* Riordina visivamente (non cambia l'ordine nel DOM) */
  order: -1;  /* Sposta prima degli elementi predefiniti */
  order: 0;   /* Predefinito */
  order: 1;   /* Sposta dopo gli elementi predefiniti */
}
```

---

## Centratura — L'Eterna Domanda

Ogni metodo per centrare il contenuto in CSS, dal semplice al blindato.

```css
/* ✅ Metodo 1: Flexbox (il più comune) */
.center-flex {
  display: flex;
  justify-content: center;  /* orizzontale */
  align-items: center;      /* verticale */
  min-height: 100vh;
}

/* ✅ Metodo 2: Grid (il più breve) */
.center-grid {
  display: grid;
  place-items: center;      /* orizzontale + verticale in una riga */
  min-height: 100vh;
}

/* ✅ Metodo 3: Margine auto (elemento blocco) */
.center-margin {
  width: 300px;
  margin: 0 auto;           /* solo orizzontale */
}

/* ✅ Metodo 4: Assoluto + Transform (supporto legacy) */
.center-absolute {
  position: absolute;
  top: 50%;
  left: 50%;
  transform: translate(-50%, -50%);
}

/* ✅ Metodo 5: Grid + margine auto (figlio singolo) */
.parent { display: grid; }
.child { margin: auto; }    /* centra su entrambi gli assi */

/* ✅ Centrare il testo */
.center-text {
  text-align: center;            /* testo orizzontale */
  line-height: 100px;            /* verticale (riga singola, altezza nota) */
}
```

---

## Pattern Flexbox Comuni

### Barra di Navigazione

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

### Riga di Card (Responsive)

```css
.card-row {
  display: flex;
  flex-wrap: wrap;
  gap: 20px;
}
.card {
  flex: 1 1 300px;  /* cresci, restringi, minimo 300px */
  max-width: 400px;
}
```

### Footer Fisso

```css
body {
  display: flex;
  flex-direction: column;
  min-height: 100vh;
}
main {
  flex: 1;  /* il main cresce per spingere il footer in basso */
}
footer {
  flex-shrink: 0;
}
```

### Layout con Sidebar

```css
.layout {
  display: flex;
  min-height: 100vh;
}
.sidebar {
  flex: 0 0 250px;  /* larghezza fissa 250px */
}
.content {
  flex: 1;          /* occupa lo spazio rimanente */
}
```

---

## Fondamenti di CSS Grid

Grid crea layout bidimensionali. Definisci righe e colonne, poi posiziona gli elementi nelle celle della griglia.

### Proprietà del Contenitore

```css
.grid {
  display: grid;

  /* Definisci colonne */
  grid-template-columns: 200px 1fr 200px;       /* fisso | flessibile | fisso */
  grid-template-columns: repeat(3, 1fr);          /* 3 colonne uguali */
  grid-template-columns: repeat(auto-fill, minmax(250px, 1fr)); /* responsive */
  grid-template-columns: repeat(auto-fit, minmax(250px, 1fr));  /* responsive, si estende */

  /* Definisci righe */
  grid-template-rows: auto 1fr auto;       /* header | contenuto | footer */
  grid-template-rows: repeat(3, 200px);    /* 3 righe, ciascuna 200px */

  /* Righe automatiche (per contenuto dinamico) */
  grid-auto-rows: minmax(100px, auto);     /* almeno 100px, cresce secondo necessità */

  /* Spazio tra le celle */
  gap: 20px;            /* uguale in entrambe le direzioni */
  gap: 20px 10px;       /* gap-riga gap-colonna */

  /* Allineamento di TUTTI gli elementi nelle loro celle */
  justify-items: start | center | end | stretch;
  align-items: start | center | end | stretch;

  /* Allineamento della GRIGLIA nel contenitore */
  justify-content: start | center | end | space-between | space-around;
  align-content: start | center | end | space-between | space-around;

  /* Abbreviazione: allinea + giustifica */
  place-items: center;         /* entrambi gli assi */
  place-content: center;       /* entrambi gli assi */
}
```

### auto-fill vs auto-fit

```css
/* auto-fill: crea quante più colonne possibili, lascia colonne vuote */
grid-template-columns: repeat(auto-fill, minmax(200px, 1fr));
/* Con 3 elementi in un contenitore da 1000px: crea 5 tracce, 2 vuote */

/* auto-fit: come auto-fill, ma comprime le tracce vuote */
grid-template-columns: repeat(auto-fit, minmax(200px, 1fr));
/* Con 3 elementi in un contenitore da 1000px: gli elementi si estendono per riempire */
```

### Posizionamento degli Elementi

```css
.item {
  /* Estendi su colonne specifiche */
  grid-column: 1 / 3;        /* inizia alla linea 1, finisce alla linea 3 (estende 2) */
  grid-column: 1 / -1;       /* estendi su TUTTE le colonne (larghezza piena) */
  grid-column: span 2;       /* estendi 2 colonne dalla posizione corrente */

  /* Estendi su righe specifiche */
  grid-row: 1 / 3;           /* inizia alla linea 1, finisce alla linea 3 */
  grid-row: span 3;          /* estendi 3 righe */

  /* Posiziona nella cella esatta */
  grid-column: 2;
  grid-row: 1;

  /* Abbreviazione: inizio-riga / inizio-col / fine-riga / fine-col */
  grid-area: 1 / 1 / 3 / 3;  /* blocco 2x2 in alto a sinistra */

  /* Sovrascrivi l'allineamento per questo elemento */
  justify-self: center;
  align-self: end;
}
```

---

## Aree Template Grid

Assegna nomi alle regioni del layout per definizioni della griglia leggibili e visive.

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

/* Responsive: impila su mobile */
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

## Pattern Grid Comuni

### Griglia di Card Responsive

```css
.card-grid {
  display: grid;
  grid-template-columns: repeat(auto-fit, minmax(280px, 1fr));
  gap: 24px;
  padding: 24px;
}
/* Le card vanno automaticamente a capo su nuove righe quando la viewport si restringe */
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

### Galleria Immagini (Simile a Masonry)

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

## Media Query

Rispondi alla dimensione della viewport, alle preferenze dell'utente e alle caratteristiche del dispositivo.

```css
/* Approccio mobile-first (consigliato) */
/* Stili base = mobile */
.container { padding: 16px; }

/* Tablet e superiori */
@media (min-width: 768px) {
  .container { padding: 24px; max-width: 720px; margin: 0 auto; }
}

/* Desktop e superiori */
@media (min-width: 1024px) {
  .container { max-width: 960px; }
}

/* Desktop grande */
@media (min-width: 1280px) {
  .container { max-width: 1200px; }
}

/* Breakpoint comuni */
/* 480px  — telefoni piccoli */
/* 768px  — tablet */
/* 1024px — desktop piccoli */
/* 1280px — desktop grandi */
/* 1536px — extra grandi */

/* Rilevamento modalità scura */
@media (prefers-color-scheme: dark) {
  :root {
    --bg: #0a0a0a;
    --text: #e0e0e0;
  }
}

/* Movimento ridotto (accessibilità) */
@media (prefers-reduced-motion: reduce) {
  * {
    animation-duration: 0.01ms !important;
    transition-duration: 0.01ms !important;
  }
}

/* Capacità hover (touch vs mouse) */
@media (hover: hover) {
  .card:hover { transform: translateY(-4px); }
}

/* Stili di stampa */
@media print {
  .no-print { display: none; }
  body { font-size: 12pt; color: #000; }
}

/* Container query (CSS moderno) */
.card-container {
  container-type: inline-size;
}
@container (min-width: 400px) {
  .card { flex-direction: row; }
}
```

---

## Proprietà Personalizzate CSS (Variabili)

Definisci valori riutilizzabili che possono essere sovrascritti per contesto. La base dei design system tematizzabili.

```css
/* Definisci su :root per accesso globale */
:root {
  /* Colori */
  --color-primary: #00e5ff;
  --color-secondary: #7b1fa2;
  --color-bg: #0a0a0a;
  --color-surface: #1a1a2e;
  --color-text: #e0e0e0;
  --color-text-muted: #888;
  --color-success: #00ff41;
  --color-error: #ff3d3d;

  /* Tipografia */
  --font-body: "Inter", -apple-system, sans-serif;
  --font-mono: "Fira Code", "Courier New", monospace;
  --font-size-sm: 0.875rem;
  --font-size-md: 1rem;
  --font-size-lg: 1.25rem;
  --font-size-xl: 2rem;

  /* Scala di spaziatura */
  --space-xs: 4px;
  --space-sm: 8px;
  --space-md: 16px;
  --space-lg: 24px;
  --space-xl: 48px;

  /* Bordi e Ombre */
  --radius-sm: 4px;
  --radius-md: 8px;
  --radius-lg: 16px;
  --shadow-sm: 0 1px 3px rgba(0, 0, 0, 0.2);
  --shadow-md: 0 4px 12px rgba(0, 0, 0, 0.3);
  --shadow-lg: 0 10px 30px rgba(0, 0, 0, 0.5);

  /* Transizioni */
  --transition-fast: 150ms ease;
  --transition-normal: 300ms ease;
}

/* Utilizzo */
.card {
  background: var(--color-surface);
  color: var(--color-text);
  padding: var(--space-lg);
  border-radius: var(--radius-md);
  box-shadow: var(--shadow-md);
  font-family: var(--font-body);
  transition: transform var(--transition-normal);
}

/* Valori di fallback */
.element {
  color: var(--color-accent, #ff6600); /* usa #ff6600 se --color-accent non è definito */
}

/* Sovrascrittura nel contesto (tematizzazione) */
[data-theme="light"] {
  --color-bg: #ffffff;
  --color-surface: #f5f5f5;
  --color-text: #1a1a1a;
}

/* Sovrascrittura nel componente */
.card-danger {
  --color-primary: var(--color-error);
}

/* Valori dinamici con calc() */
.responsive-padding {
  padding: calc(var(--space-md) + 1vw);
}

/* Variabili nelle media query */
@media (max-width: 768px) {
  :root {
    --font-size-xl: 1.5rem;
    --space-lg: 16px;
  }
}
```

---

## Funzionalità CSS Moderne

```css
/* aspect-ratio — mantieni le proporzioni */
.video-container {
  aspect-ratio: 16 / 9;
  width: 100%;
}
.avatar {
  aspect-ratio: 1;       /* quadrato perfetto */
  border-radius: 50%;
}

/* clamp() — valori responsive senza media query */
.title {
  font-size: clamp(1.5rem, 4vw, 3rem);  /* min, preferito, max */
}
.container {
  width: clamp(300px, 90%, 1200px);
}
.card {
  padding: clamp(16px, 3vw, 48px);
}

/* min() e max() */
.sidebar {
  width: min(300px, 30%);   /* il più piccolo dei due */
}
.hero {
  height: max(400px, 50vh); /* il più grande dei due */
}

/* :is() e :where() — riduci la ripetizione dei selettori */
/* Prima: */
.card h1, .card h2, .card h3 { color: white; }
/* Dopo: */
.card :is(h1, h2, h3) { color: white; }

/* :has() — selettore genitore (rivoluzionario) */
.card:has(img) { padding: 0; }                     /* card che contiene un'immagine */
.form:has(:invalid) .submit { opacity: 0.5; }      /* form con input non validi */
.nav:has(.dropdown:hover) { background: #111; }    /* nav quando il dropdown è in hover */

/* Proprietà logiche (supporto RTL) */
.element {
  margin-inline-start: 20px;   /* sinistra in LTR, destra in RTL */
  padding-block: 10px;          /* alto + basso */
  border-inline-end: 1px solid; /* destra in LTR, sinistra in RTL */
}

/* scroll-snap — scorrimento fluido con aggancio */
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

/* accent-color — personalizza i controlli nativi dei form */
input[type="checkbox"],
input[type="radio"],
input[type="range"] {
  accent-color: var(--color-primary);
}
```

---

## Flexbox vs Grid — Quando Usare Quale

| Scenario | Usa | Perché |
|---|---|---|
| Barra di navigazione | Flexbox | Riga unidimensionale con spaziatura |
| Griglia di card | Grid | Bidimensionale, righe di altezza uguale |
| Layout form | Grid | Etichette e input allineati in colonne |
| Centrare un elemento | Grid | `place-items: center` è il più breve |
| Sidebar + contenuto | Grid o Flexbox | Grid per aree template, Flex per divisione semplice |
| Lista card responsive | Grid | `auto-fit` + `minmax` gestisce tutto |
| Spazio tra elementi | Flexbox | `justify-content: space-between` |
| Widget dashboard | Grid | Estendi su più righe/colonne |
| Sezioni impilate verticalmente | Flexbox | Direzione colonna con `gap` |
| Layout pagina complesso | Grid | Aree template per regioni con nome |

**Regola pratica**: Flexbox per i componenti (navbar, pulsanti, layout piccoli). Grid per layout a livello di pagina e tutto ciò che necessita di righe E colonne.

---

## Reset e Stili di Base

Un reset minimale per un rendering coerente tra i browser.

```css
/* Reset CSS Moderno */
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

/* Accessibilità: rispetta le preferenze dell'utente */
@media (prefers-reduced-motion: reduce) {
  html { scroll-behavior: auto; }
}
```

---

## Riferimento Rapido

| Proprietà | Flexbox | Grid |
|---|---|---|
| Attivare | `display: flex` | `display: grid` |
| Direzione | `flex-direction` | `grid-template-columns/rows` |
| A capo | `flex-wrap: wrap` | Automatico con `auto-fit` |
| Spazio | `gap` | `gap` |
| Allineamento orizzontale | `justify-content` | `justify-items` / `justify-content` |
| Allineamento verticale | `align-items` | `align-items` / `align-content` |
| Dimensionamento elementi | `flex: 1 0 200px` | `minmax(200px, 1fr)` |
| Centra tutto | `justify-content + align-items: center` | `place-items: center` |
| Responsive | `flex-wrap` + media query | `auto-fit` + `minmax()` |

---

## Fine della Trasmissione

Questa cheatsheet copre le tecniche di layout CSS che alimentano ogni sito web moderno — dal centrare un div alla costruzione di dashboard responsive complesse. Flexbox per il flusso unidimensionale, Grid per i layout bidimensionali e le variabili CSS per design system manutenibili. Salvala nei preferiti, consultala durante i colloqui frontend e smetti di lottare con il CSS. Il motore di layout ora lavora per te.
