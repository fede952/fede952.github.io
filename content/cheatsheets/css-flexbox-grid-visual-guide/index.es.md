---
title: "Cheatsheet de Layouts CSS: Guía Visual de Flexbox y Grid"
description: "La referencia definitiva de CSS Flexbox y Grid. Aprende a centrar divs, construir layouts responsive, dominar media queries y usar variables CSS modernas con ejemplos para copiar y pegar."
date: 2026-02-10
tags: ["css", "cheatsheet", "frontend", "flexbox", "grid", "web-dev"]
keywords: ["css flexbox cheatsheet", "css grid tutorial", "centrar div css", "aprender web dev", "layout responsive css", "media queries", "variables css", "entrevista frontend", "flexbox vs grid", "guía layout css", "ejemplos css grid", "flexbox align items", "propiedad gap css", "css moderno 2026"]
draft: false
schema_json: >
  {
    "@context": "https://schema.org",
    "@type": "TechArticle",
    "name": "Cheatsheet de Layouts CSS: Guía Visual de Flexbox y Grid",
    "description": "Referencia visual completa para layouts CSS Flexbox y Grid con patrones de diseño responsive y variables CSS modernas.",
    "proficiencyLevel": "Intermediate",
    "inLanguage": "es"
  }
---

## Motor de Renderizado en Línea

El layout CSS es la habilidad que separa a los desarrolladores que construyen de los que luchan. Flexbox maneja el flujo unidimensional — filas o columnas. Grid maneja layouts bidimensionales — filas Y columnas simultáneamente. Juntos, reemplazan cada hack con float, clearfix y truco de posicionamiento de la última década. Esta cheatsheet cubre ambos sistemas con fragmentos listos para producción, patrones responsive y las variables CSS modernas que mantienen tu código mantenible. Cada técnica aquí es lo que los entrevistadores frontend esperan que sepas. Copia, pega, despliega.

---

## Fundamentos de Flexbox

Flexbox funciona en una dirección a la vez — ya sea una fila o una columna. El contenedor padre controla el layout; los hijos son los elementos flex.

### Propiedades del Contenedor

```css
.container {
  display: flex;            /* Activar flexbox */

  /* Dirección: cómo fluyen los elementos */
  flex-direction: row;             /* → de izquierda a derecha (por defecto) */
  flex-direction: row-reverse;     /* ← de derecha a izquierda */
  flex-direction: column;          /* ↓ de arriba a abajo */
  flex-direction: column-reverse;  /* ↑ de abajo a arriba */

  /* Envoltura: qué pasa cuando los elementos desbordan */
  flex-wrap: nowrap;   /* Línea única, los elementos se encogen (por defecto) */
  flex-wrap: wrap;     /* Los elementos pasan a la siguiente línea */

  /* Alineación del eje principal (dirección del flujo) */
  justify-content: flex-start;     /* Agrupar al inicio |||....... */
  justify-content: flex-end;       /* Agrupar al final  .......|||*/
  justify-content: center;         /* Centrar           ...||| ...*/
  justify-content: space-between;  /* Primero y último en los bordes |..|..|*/
  justify-content: space-around;   /* Espacio igual alrededor       .|..|..|.*/
  justify-content: space-evenly;   /* Espacio igual entre           .|..|..|.*/

  /* Alineación del eje transversal (perpendicular al flujo) */
  align-items: stretch;      /* Llenar la altura del contenedor (por defecto) */
  align-items: flex-start;   /* Alinear arriba */
  align-items: flex-end;     /* Alinear abajo */
  align-items: center;       /* Centrar verticalmente */
  align-items: baseline;     /* Alinear líneas base del texto */

  /* Espacio entre elementos (reemplazo moderno de márgenes) */
  gap: 20px;            /* Espacio igual en ambas direcciones */
  gap: 20px 10px;       /* gap-fila gap-columna */
}
```

### Propiedades de los Elementos

```css
.item {
  /* Crecimiento: cuánto espacio extra toma este elemento */
  flex-grow: 0;   /* No crecer (por defecto) */
  flex-grow: 1;   /* Tomar parte igual del espacio extra */
  flex-grow: 2;   /* Tomar el doble */

  /* Encogimiento: cuánto se encoge este elemento cuando el espacio es limitado */
  flex-shrink: 1;   /* Encoger igualmente (por defecto) */
  flex-shrink: 0;   /* Nunca encoger (mantener tamaño original) */

  /* Base: tamaño inicial antes de crecer/encoger */
  flex-basis: auto;   /* Usar tamaño del contenido (por defecto) */
  flex-basis: 200px;  /* Comenzar en 200px */
  flex-basis: 0;      /* Ignorar tamaño del contenido, distribuir todo el espacio */

  /* Abreviatura: crecimiento encogimiento base */
  flex: 1;          /* flex: 1 1 0 — crecer igualmente, ignorar contenido */
  flex: 0 0 300px;  /* Fijo 300px, no crecer, no encoger */
  flex: 1 0 200px;  /* Comenzar en 200px, puede crecer, nunca encoge */

  /* Sobreescribir alineación del eje transversal solo para este elemento */
  align-self: flex-start;
  align-self: center;
  align-self: flex-end;

  /* Reordenar visualmente (no cambia el orden del DOM) */
  order: -1;  /* Mover antes de los elementos por defecto */
  order: 0;   /* Por defecto */
  order: 1;   /* Mover después de los elementos por defecto */
}
```

---

## Centrado — La Eterna Pregunta

Todos los métodos para centrar contenido en CSS, del simple al infalible.

```css
/* ✅ Método 1: Flexbox (el más común) */
.center-flex {
  display: flex;
  justify-content: center;  /* horizontal */
  align-items: center;      /* vertical */
  min-height: 100vh;
}

/* ✅ Método 2: Grid (el más corto) */
.center-grid {
  display: grid;
  place-items: center;      /* horizontal + vertical en una línea */
  min-height: 100vh;
}

/* ✅ Método 3: Margen auto (elemento de bloque) */
.center-margin {
  width: 300px;
  margin: 0 auto;           /* solo horizontal */
}

/* ✅ Método 4: Absoluto + Transform (soporte legacy) */
.center-absolute {
  position: absolute;
  top: 50%;
  left: 50%;
  transform: translate(-50%, -50%);
}

/* ✅ Método 5: Grid + margen auto (hijo único) */
.parent { display: grid; }
.child { margin: auto; }    /* centra en ambos ejes */

/* ✅ Centrar texto */
.center-text {
  text-align: center;            /* texto horizontal */
  line-height: 100px;            /* vertical (línea única, altura conocida) */
}
```

---

## Patrones Comunes de Flexbox

### Barra de Navegación

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

### Fila de Cards (Responsive)

```css
.card-row {
  display: flex;
  flex-wrap: wrap;
  gap: 20px;
}
.card {
  flex: 1 1 300px;  /* crecer, encoger, mínimo 300px */
  max-width: 400px;
}
```

### Footer Fijo

```css
body {
  display: flex;
  flex-direction: column;
  min-height: 100vh;
}
main {
  flex: 1;  /* el main crece para empujar el footer hacia abajo */
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
  flex: 0 0 250px;  /* ancho fijo de 250px */
}
.content {
  flex: 1;          /* ocupa el espacio restante */
}
```

---

## Fundamentos de CSS Grid

Grid crea layouts bidimensionales. Define filas y columnas, luego coloca elementos en las celdas de la cuadrícula.

### Propiedades del Contenedor

```css
.grid {
  display: grid;

  /* Definir columnas */
  grid-template-columns: 200px 1fr 200px;       /* fijo | flexible | fijo */
  grid-template-columns: repeat(3, 1fr);          /* 3 columnas iguales */
  grid-template-columns: repeat(auto-fill, minmax(250px, 1fr)); /* responsive */
  grid-template-columns: repeat(auto-fit, minmax(250px, 1fr));  /* responsive, se estira */

  /* Definir filas */
  grid-template-rows: auto 1fr auto;       /* header | contenido | footer */
  grid-template-rows: repeat(3, 200px);    /* 3 filas, cada una 200px */

  /* Filas automáticas (para contenido dinámico) */
  grid-auto-rows: minmax(100px, auto);     /* al menos 100px, crece según necesidad */

  /* Espacio entre celdas */
  gap: 20px;            /* igual en ambas direcciones */
  gap: 20px 10px;       /* gap-fila gap-columna */

  /* Alineación de TODOS los elementos dentro de sus celdas */
  justify-items: start | center | end | stretch;
  align-items: start | center | end | stretch;

  /* Alineación de la CUADRÍCULA dentro del contenedor */
  justify-content: start | center | end | space-between | space-around;
  align-content: start | center | end | space-between | space-around;

  /* Abreviatura: alinear + justificar */
  place-items: center;         /* ambos ejes */
  place-content: center;       /* ambos ejes */
}
```

### auto-fill vs auto-fit

```css
/* auto-fill: crea tantas columnas como quepan, deja columnas vacías */
grid-template-columns: repeat(auto-fill, minmax(200px, 1fr));
/* Con 3 elementos en un contenedor de 1000px: crea 5 pistas, 2 vacías */

/* auto-fit: igual que auto-fill, pero colapsa las pistas vacías */
grid-template-columns: repeat(auto-fit, minmax(200px, 1fr));
/* Con 3 elementos en un contenedor de 1000px: los elementos se estiran para llenar */
```

### Colocación de Elementos

```css
.item {
  /* Extender sobre columnas específicas */
  grid-column: 1 / 3;        /* empieza en línea 1, termina en línea 3 (abarca 2) */
  grid-column: 1 / -1;       /* abarcar TODAS las columnas (ancho completo) */
  grid-column: span 2;       /* abarcar 2 columnas desde la posición actual */

  /* Extender sobre filas específicas */
  grid-row: 1 / 3;           /* empieza en línea 1, termina en línea 3 */
  grid-row: span 3;          /* abarcar 3 filas */

  /* Colocar en celda exacta */
  grid-column: 2;
  grid-row: 1;

  /* Abreviatura: inicio-fila / inicio-col / fin-fila / fin-col */
  grid-area: 1 / 1 / 3 / 3;  /* bloque 2x2 arriba a la izquierda */

  /* Sobreescribir alineación para este elemento */
  justify-self: center;
  align-self: end;
}
```

---

## Áreas de Plantilla Grid

Nombra las regiones de tu layout para definiciones de cuadrícula legibles y visuales.

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

/* Responsive: apilar en móvil */
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

## Patrones Comunes de Grid

### Cuadrícula de Cards Responsive

```css
.card-grid {
  display: grid;
  grid-template-columns: repeat(auto-fit, minmax(280px, 1fr));
  gap: 24px;
  padding: 24px;
}
/* Las cards pasan automáticamente a nuevas filas cuando la viewport se reduce */
```

### Layout de Dashboard

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

### Galería de Imágenes (Tipo Masonry)

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

Responde al tamaño de la viewport, las preferencias del usuario y las características del dispositivo.

```css
/* Enfoque mobile-first (recomendado) */
/* Estilos base = móvil */
.container { padding: 16px; }

/* Tablet y superiores */
@media (min-width: 768px) {
  .container { padding: 24px; max-width: 720px; margin: 0 auto; }
}

/* Escritorio y superiores */
@media (min-width: 1024px) {
  .container { max-width: 960px; }
}

/* Escritorio grande */
@media (min-width: 1280px) {
  .container { max-width: 1200px; }
}

/* Breakpoints comunes */
/* 480px  — teléfonos pequeños */
/* 768px  — tablets */
/* 1024px — escritorios pequeños */
/* 1280px — escritorios grandes */
/* 1536px — extra grandes */

/* Detección de modo oscuro */
@media (prefers-color-scheme: dark) {
  :root {
    --bg: #0a0a0a;
    --text: #e0e0e0;
  }
}

/* Movimiento reducido (accesibilidad) */
@media (prefers-reduced-motion: reduce) {
  * {
    animation-duration: 0.01ms !important;
    transition-duration: 0.01ms !important;
  }
}

/* Capacidad de hover (táctil vs ratón) */
@media (hover: hover) {
  .card:hover { transform: translateY(-4px); }
}

/* Estilos de impresión */
@media print {
  .no-print { display: none; }
  body { font-size: 12pt; color: #000; }
}

/* Consultas de contenedor (CSS moderno) */
.card-container {
  container-type: inline-size;
}
@container (min-width: 400px) {
  .card { flex-direction: row; }
}
```

---

## Propiedades Personalizadas CSS (Variables)

Define valores reutilizables que pueden sobreescribirse por contexto. La base de los sistemas de diseño con temas.

```css
/* Definir en :root para acceso global */
:root {
  /* Colores */
  --color-primary: #00e5ff;
  --color-secondary: #7b1fa2;
  --color-bg: #0a0a0a;
  --color-surface: #1a1a2e;
  --color-text: #e0e0e0;
  --color-text-muted: #888;
  --color-success: #00ff41;
  --color-error: #ff3d3d;

  /* Tipografía */
  --font-body: "Inter", -apple-system, sans-serif;
  --font-mono: "Fira Code", "Courier New", monospace;
  --font-size-sm: 0.875rem;
  --font-size-md: 1rem;
  --font-size-lg: 1.25rem;
  --font-size-xl: 2rem;

  /* Escala de espaciado */
  --space-xs: 4px;
  --space-sm: 8px;
  --space-md: 16px;
  --space-lg: 24px;
  --space-xl: 48px;

  /* Bordes y Sombras */
  --radius-sm: 4px;
  --radius-md: 8px;
  --radius-lg: 16px;
  --shadow-sm: 0 1px 3px rgba(0, 0, 0, 0.2);
  --shadow-md: 0 4px 12px rgba(0, 0, 0, 0.3);
  --shadow-lg: 0 10px 30px rgba(0, 0, 0, 0.5);

  /* Transiciones */
  --transition-fast: 150ms ease;
  --transition-normal: 300ms ease;
}

/* Uso */
.card {
  background: var(--color-surface);
  color: var(--color-text);
  padding: var(--space-lg);
  border-radius: var(--radius-md);
  box-shadow: var(--shadow-md);
  font-family: var(--font-body);
  transition: transform var(--transition-normal);
}

/* Valores de respaldo */
.element {
  color: var(--color-accent, #ff6600); /* usa #ff6600 si --color-accent no está definido */
}

/* Sobreescritura en contexto (tematización) */
[data-theme="light"] {
  --color-bg: #ffffff;
  --color-surface: #f5f5f5;
  --color-text: #1a1a1a;
}

/* Sobreescritura en componente */
.card-danger {
  --color-primary: var(--color-error);
}

/* Valores dinámicos con calc() */
.responsive-padding {
  padding: calc(var(--space-md) + 1vw);
}

/* Variables en media queries */
@media (max-width: 768px) {
  :root {
    --font-size-xl: 1.5rem;
    --space-lg: 16px;
  }
}
```

---

## Funcionalidades CSS Modernas

```css
/* aspect-ratio — mantener proporciones */
.video-container {
  aspect-ratio: 16 / 9;
  width: 100%;
}
.avatar {
  aspect-ratio: 1;       /* cuadrado perfecto */
  border-radius: 50%;
}

/* clamp() — valores responsive sin media queries */
.title {
  font-size: clamp(1.5rem, 4vw, 3rem);  /* mín, preferido, máx */
}
.container {
  width: clamp(300px, 90%, 1200px);
}
.card {
  padding: clamp(16px, 3vw, 48px);
}

/* min() y max() */
.sidebar {
  width: min(300px, 30%);   /* el que sea menor */
}
.hero {
  height: max(400px, 50vh); /* el que sea mayor */
}

/* :is() y :where() — reducir repetición de selectores */
/* Antes: */
.card h1, .card h2, .card h3 { color: white; }
/* Después: */
.card :is(h1, h2, h3) { color: white; }

/* :has() — selector de padre (revolucionario) */
.card:has(img) { padding: 0; }                     /* card que contiene una imagen */
.form:has(:invalid) .submit { opacity: 0.5; }      /* formulario con inputs inválidos */
.nav:has(.dropdown:hover) { background: #111; }    /* nav cuando el dropdown tiene hover */

/* Propiedades lógicas (soporte RTL) */
.element {
  margin-inline-start: 20px;   /* izquierda en LTR, derecha en RTL */
  padding-block: 10px;          /* arriba + abajo */
  border-inline-end: 1px solid; /* derecha en LTR, izquierda en RTL */
}

/* scroll-snap — desplazamiento fluido con ajuste */
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

/* accent-color — personalizar controles nativos de formulario */
input[type="checkbox"],
input[type="radio"],
input[type="range"] {
  accent-color: var(--color-primary);
}
```

---

## Flexbox vs Grid — Cuándo Usar Cada Uno

| Escenario | Usar | Por qué |
|---|---|---|
| Barra de navegación | Flexbox | Fila unidimensional con espaciado |
| Cuadrícula de cards | Grid | Bidimensional, filas de igual altura |
| Layout de formulario | Grid | Etiquetas e inputs alineados en columnas |
| Centrar un elemento | Grid | `place-items: center` es lo más corto |
| Sidebar + contenido | Grid o Flexbox | Grid para áreas de plantilla, Flex para división simple |
| Lista de cards responsive | Grid | `auto-fit` + `minmax` lo maneja todo |
| Espacio entre elementos | Flexbox | `justify-content: space-between` |
| Widgets de dashboard | Grid | Abarcar múltiples filas/columnas |
| Secciones apiladas verticalmente | Flexbox | Dirección columna con `gap` |
| Layout de página complejo | Grid | Áreas de plantilla para regiones con nombre |

**Regla general**: Flexbox para componentes (barras de navegación, botones, layouts pequeños). Grid para layouts a nivel de página y todo lo que necesite filas Y columnas.

---

## Reset y Estilos Base

Un reset mínimo para renderizado consistente entre navegadores.

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

/* Accesibilidad: respetar las preferencias del usuario */
@media (prefers-reduced-motion: reduce) {
  html { scroll-behavior: auto; }
}
```

---

## Referencia Rápida

| Propiedad | Flexbox | Grid |
|---|---|---|
| Activar | `display: flex` | `display: grid` |
| Dirección | `flex-direction` | `grid-template-columns/rows` |
| Envoltura | `flex-wrap: wrap` | Automático con `auto-fit` |
| Espacio | `gap` | `gap` |
| Alineación horizontal | `justify-content` | `justify-items` / `justify-content` |
| Alineación vertical | `align-items` | `align-items` / `align-content` |
| Tamaño de elementos | `flex: 1 0 200px` | `minmax(200px, 1fr)` |
| Centrar todo | `justify-content + align-items: center` | `place-items: center` |
| Responsive | `flex-wrap` + media queries | `auto-fit` + `minmax()` |

---

## Fin de la Transmisión

Esta cheatsheet cubre las técnicas de layout CSS que impulsan cada sitio web moderno — desde centrar un div hasta construir dashboards responsive complejos. Flexbox para flujo unidimensional, Grid para layouts bidimensionales y variables CSS para sistemas de diseño mantenibles. Guárdala en marcadores, consúltala en entrevistas frontend y deja de pelear con CSS. El motor de layout ahora trabaja para ti.
