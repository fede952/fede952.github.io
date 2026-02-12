---
title: "Cheatsheet de Layouts CSS: Guia Visual Flexbox & Grid"
description: "A referência definitiva de CSS Flexbox e Grid. Aprenda a centralizar divs, construir layouts responsivos, dominar media queries e usar variáveis CSS modernas com exemplos para copiar e colar."
date: 2026-02-10
tags: ["css", "cheatsheet", "frontend", "flexbox", "grid", "web-dev"]
keywords: ["css flexbox cheatsheet", "css grid tutorial", "centralizar div css", "aprender web dev", "layout responsivo css", "media queries", "variáveis css", "entrevista frontend", "flexbox vs grid", "guia layout css", "exemplos css grid", "flexbox align items", "propriedade gap css", "css moderno 2026"]
draft: false
schema_json: >
  {
    "@context": "https://schema.org",
    "@type": "TechArticle",
    "name": "Cheatsheet de Layouts CSS: Guia Visual Flexbox & Grid",
    "description": "Referência visual completa para layouts CSS Flexbox e Grid com padrões de design responsivo e variáveis CSS modernas.",
    "proficiencyLevel": "Intermediate",
    "inLanguage": "pt"
  }
---

## Motor de Renderização Online

O layout CSS é a habilidade que separa desenvolvedores que constroem dos que lutam. Flexbox lida com fluxo unidimensional — linhas ou colunas. Grid lida com layouts bidimensionais — linhas E colunas simultaneamente. Juntos, substituem cada hack com float, clearfix e truque de posicionamento da última década. Esta cheatsheet cobre ambos os sistemas com trechos prontos para produção, padrões responsivos e as variáveis CSS modernas que mantêm seu código sustentável. Cada técnica aqui é o que entrevistadores frontend esperam que você saiba. Copie, cole, publique.

---

## Fundamentos do Flexbox

Flexbox funciona em uma direção de cada vez — seja uma linha ou uma coluna. O contêiner pai controla o layout; os filhos são os itens flex.

### Propriedades do Contêiner

```css
.container {
  display: flex;            /* Ativar flexbox */

  /* Direção: como os itens fluem */
  flex-direction: row;             /* → da esquerda para a direita (padrão) */
  flex-direction: row-reverse;     /* ← da direita para a esquerda */
  flex-direction: column;          /* ↓ de cima para baixo */
  flex-direction: column-reverse;  /* ↑ de baixo para cima */

  /* Quebra de linha: o que acontece quando os itens transbordam */
  flex-wrap: nowrap;   /* Linha única, itens encolhem (padrão) */
  flex-wrap: wrap;     /* Itens quebram para a próxima linha */

  /* Alinhamento do eixo principal (direção do fluxo) */
  justify-content: flex-start;     /* Agrupar no início |||....... */
  justify-content: flex-end;       /* Agrupar no final  .......|||*/
  justify-content: center;         /* Centralizar       ...||| ...*/
  justify-content: space-between;  /* Primeiro e último nas bordas |..|..|*/
  justify-content: space-around;   /* Espaço igual ao redor        .|..|..|.*/
  justify-content: space-evenly;   /* Espaço igual entre           .|..|..|.*/

  /* Alinhamento do eixo transversal (perpendicular ao fluxo) */
  align-items: stretch;      /* Preencher a altura do contêiner (padrão) */
  align-items: flex-start;   /* Alinhar no topo */
  align-items: flex-end;     /* Alinhar na base */
  align-items: center;       /* Centralizar verticalmente */
  align-items: baseline;     /* Alinhar linhas de base do texto */

  /* Espaçamento entre itens (substituto moderno das margens) */
  gap: 20px;            /* Espaço igual em ambas as direções */
  gap: 20px 10px;       /* gap-linha gap-coluna */
}
```

### Propriedades dos Itens

```css
.item {
  /* Crescimento: quanto espaço extra este item ocupa */
  flex-grow: 0;   /* Não crescer (padrão) */
  flex-grow: 1;   /* Ocupar parte igual do espaço extra */
  flex-grow: 2;   /* Ocupar o dobro */

  /* Encolhimento: quanto este item encolhe quando o espaço é limitado */
  flex-shrink: 1;   /* Encolher igualmente (padrão) */
  flex-shrink: 0;   /* Nunca encolher (manter tamanho original) */

  /* Base: tamanho inicial antes de crescer/encolher */
  flex-basis: auto;   /* Usar tamanho do conteúdo (padrão) */
  flex-basis: 200px;  /* Começar em 200px */
  flex-basis: 0;      /* Ignorar tamanho do conteúdo, distribuir todo o espaço */

  /* Abreviação: crescimento encolhimento base */
  flex: 1;          /* flex: 1 1 0 — crescer igualmente, ignorar conteúdo */
  flex: 0 0 300px;  /* Fixo 300px, não cresce, não encolhe */
  flex: 1 0 200px;  /* Começar em 200px, pode crescer, nunca encolhe */

  /* Sobrescrever alinhamento do eixo transversal apenas para este item */
  align-self: flex-start;
  align-self: center;
  align-self: flex-end;

  /* Reordenar visualmente (não altera a ordem do DOM) */
  order: -1;  /* Mover antes dos itens padrão */
  order: 0;   /* Padrão */
  order: 1;   /* Mover após os itens padrão */
}
```

---

## Centralização — A Eterna Questão

Todos os métodos para centralizar conteúdo em CSS, do simples ao à prova de balas.

```css
/* ✅ Método 1: Flexbox (mais comum) */
.center-flex {
  display: flex;
  justify-content: center;  /* horizontal */
  align-items: center;      /* vertical */
  min-height: 100vh;
}

/* ✅ Método 2: Grid (mais curto) */
.center-grid {
  display: grid;
  place-items: center;      /* horizontal + vertical em uma linha */
  min-height: 100vh;
}

/* ✅ Método 3: Margem auto (elemento de bloco) */
.center-margin {
  width: 300px;
  margin: 0 auto;           /* apenas horizontal */
}

/* ✅ Método 4: Absoluto + Transform (suporte legado) */
.center-absolute {
  position: absolute;
  top: 50%;
  left: 50%;
  transform: translate(-50%, -50%);
}

/* ✅ Método 5: Grid + margem auto (filho único) */
.parent { display: grid; }
.child { margin: auto; }    /* centraliza em ambos os eixos */

/* ✅ Centralizar texto */
.center-text {
  text-align: center;            /* texto horizontal */
  line-height: 100px;            /* vertical (linha única, altura conhecida) */
}
```

---

## Padrões Comuns de Flexbox

### Barra de Navegação

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

### Linha de Cards (Responsiva)

```css
.card-row {
  display: flex;
  flex-wrap: wrap;
  gap: 20px;
}
.card {
  flex: 1 1 300px;  /* crescer, encolher, mínimo 300px */
  max-width: 400px;
}
```

### Footer Fixo

```css
body {
  display: flex;
  flex-direction: column;
  min-height: 100vh;
}
main {
  flex: 1;  /* o main cresce para empurrar o footer para baixo */
}
footer {
  flex-shrink: 0;
}
```

### Layout com Sidebar

```css
.layout {
  display: flex;
  min-height: 100vh;
}
.sidebar {
  flex: 0 0 250px;  /* largura fixa de 250px */
}
.content {
  flex: 1;          /* ocupa o espaço restante */
}
```

---

## Fundamentos do CSS Grid

Grid cria layouts bidimensionais. Defina linhas e colunas, depois posicione itens nas células da grade.

### Propriedades do Contêiner

```css
.grid {
  display: grid;

  /* Definir colunas */
  grid-template-columns: 200px 1fr 200px;       /* fixo | flexível | fixo */
  grid-template-columns: repeat(3, 1fr);          /* 3 colunas iguais */
  grid-template-columns: repeat(auto-fill, minmax(250px, 1fr)); /* responsivo */
  grid-template-columns: repeat(auto-fit, minmax(250px, 1fr));  /* responsivo, estica */

  /* Definir linhas */
  grid-template-rows: auto 1fr auto;       /* header | conteúdo | footer */
  grid-template-rows: repeat(3, 200px);    /* 3 linhas, cada uma 200px */

  /* Linhas automáticas (para conteúdo dinâmico) */
  grid-auto-rows: minmax(100px, auto);     /* pelo menos 100px, cresce conforme necessário */

  /* Espaçamento entre células */
  gap: 20px;            /* igual em ambas as direções */
  gap: 20px 10px;       /* gap-linha gap-coluna */

  /* Alinhamento de TODOS os itens dentro de suas células */
  justify-items: start | center | end | stretch;
  align-items: start | center | end | stretch;

  /* Alinhamento da GRADE dentro do contêiner */
  justify-content: start | center | end | space-between | space-around;
  align-content: start | center | end | space-between | space-around;

  /* Abreviação: alinhar + justificar */
  place-items: center;         /* ambos os eixos */
  place-content: center;       /* ambos os eixos */
}
```

### auto-fill vs auto-fit

```css
/* auto-fill: cria quantas colunas couberem, deixa colunas vazias */
grid-template-columns: repeat(auto-fill, minmax(200px, 1fr));
/* Com 3 itens em um contêiner de 1000px: cria 5 faixas, 2 vazias */

/* auto-fit: igual ao auto-fill, mas colapsa faixas vazias */
grid-template-columns: repeat(auto-fit, minmax(200px, 1fr));
/* Com 3 itens em um contêiner de 1000px: itens esticam para preencher */
```

### Posicionamento de Itens

```css
.item {
  /* Abranger colunas específicas */
  grid-column: 1 / 3;        /* começa na linha 1, termina na linha 3 (abrange 2) */
  grid-column: 1 / -1;       /* abranger TODAS as colunas (largura total) */
  grid-column: span 2;       /* abranger 2 colunas a partir da posição atual */

  /* Abranger linhas específicas */
  grid-row: 1 / 3;           /* começa na linha 1, termina na linha 3 */
  grid-row: span 3;          /* abranger 3 linhas */

  /* Posicionar na célula exata */
  grid-column: 2;
  grid-row: 1;

  /* Abreviação: início-linha / início-col / fim-linha / fim-col */
  grid-area: 1 / 1 / 3 / 3;  /* bloco 2x2 no canto superior esquerdo */

  /* Sobrescrever alinhamento para este item */
  justify-self: center;
  align-self: end;
}
```

---

## Áreas de Template Grid

Nomeie as regiões do seu layout para definições de grade legíveis e visuais.

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

/* Responsivo: empilhar no mobile */
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

## Padrões Comuns de Grid

### Grade de Cards Responsiva

```css
.card-grid {
  display: grid;
  grid-template-columns: repeat(auto-fit, minmax(280px, 1fr));
  gap: 24px;
  padding: 24px;
}
/* Os cards quebram automaticamente para novas linhas quando a viewport diminui */
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

### Galeria de Imagens (Estilo Masonry)

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

Responda ao tamanho da viewport, preferências do usuário e recursos do dispositivo.

```css
/* Abordagem mobile-first (recomendada) */
/* Estilos base = mobile */
.container { padding: 16px; }

/* Tablet e acima */
@media (min-width: 768px) {
  .container { padding: 24px; max-width: 720px; margin: 0 auto; }
}

/* Desktop e acima */
@media (min-width: 1024px) {
  .container { max-width: 960px; }
}

/* Desktop grande */
@media (min-width: 1280px) {
  .container { max-width: 1200px; }
}

/* Breakpoints comuns */
/* 480px  — smartphones pequenos */
/* 768px  — tablets */
/* 1024px — desktops pequenos */
/* 1280px — desktops grandes */
/* 1536px — extra grandes */

/* Detecção de modo escuro */
@media (prefers-color-scheme: dark) {
  :root {
    --bg: #0a0a0a;
    --text: #e0e0e0;
  }
}

/* Movimento reduzido (acessibilidade) */
@media (prefers-reduced-motion: reduce) {
  * {
    animation-duration: 0.01ms !important;
    transition-duration: 0.01ms !important;
  }
}

/* Capacidade de hover (toque vs mouse) */
@media (hover: hover) {
  .card:hover { transform: translateY(-4px); }
}

/* Estilos de impressão */
@media print {
  .no-print { display: none; }
  body { font-size: 12pt; color: #000; }
}

/* Consultas de contêiner (CSS moderno) */
.card-container {
  container-type: inline-size;
}
@container (min-width: 400px) {
  .card { flex-direction: row; }
}
```

---

## Propriedades Personalizadas CSS (Variáveis)

Defina valores reutilizáveis que podem ser sobrescritos por contexto. A base de sistemas de design tematizáveis.

```css
/* Definir em :root para acesso global */
:root {
  /* Cores */
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

  /* Escala de espaçamento */
  --space-xs: 4px;
  --space-sm: 8px;
  --space-md: 16px;
  --space-lg: 24px;
  --space-xl: 48px;

  /* Bordas e Sombras */
  --radius-sm: 4px;
  --radius-md: 8px;
  --radius-lg: 16px;
  --shadow-sm: 0 1px 3px rgba(0, 0, 0, 0.2);
  --shadow-md: 0 4px 12px rgba(0, 0, 0, 0.3);
  --shadow-lg: 0 10px 30px rgba(0, 0, 0, 0.5);

  /* Transições */
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

/* Valores de fallback */
.element {
  color: var(--color-accent, #ff6600); /* usa #ff6600 se --color-accent não está definido */
}

/* Sobrescrita no contexto (tematização) */
[data-theme="light"] {
  --color-bg: #ffffff;
  --color-surface: #f5f5f5;
  --color-text: #1a1a1a;
}

/* Sobrescrita no componente */
.card-danger {
  --color-primary: var(--color-error);
}

/* Valores dinâmicos com calc() */
.responsive-padding {
  padding: calc(var(--space-md) + 1vw);
}

/* Variáveis em media queries */
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
/* aspect-ratio — manter proporções */
.video-container {
  aspect-ratio: 16 / 9;
  width: 100%;
}
.avatar {
  aspect-ratio: 1;       /* quadrado perfeito */
  border-radius: 50%;
}

/* clamp() — valores responsivos sem media queries */
.title {
  font-size: clamp(1.5rem, 4vw, 3rem);  /* mín, preferido, máx */
}
.container {
  width: clamp(300px, 90%, 1200px);
}
.card {
  padding: clamp(16px, 3vw, 48px);
}

/* min() e max() */
.sidebar {
  width: min(300px, 30%);   /* o que for menor */
}
.hero {
  height: max(400px, 50vh); /* o que for maior */
}

/* :is() e :where() — reduzir repetição de seletores */
/* Antes: */
.card h1, .card h2, .card h3 { color: white; }
/* Depois: */
.card :is(h1, h2, h3) { color: white; }

/* :has() — seletor pai (revolucionário) */
.card:has(img) { padding: 0; }                     /* card que contém uma imagem */
.form:has(:invalid) .submit { opacity: 0.5; }      /* formulário com inputs inválidos */
.nav:has(.dropdown:hover) { background: #111; }    /* nav quando o dropdown está em hover */

/* Propriedades lógicas (suporte RTL) */
.element {
  margin-inline-start: 20px;   /* esquerda em LTR, direita em RTL */
  padding-block: 10px;          /* topo + base */
  border-inline-end: 1px solid; /* direita em LTR, esquerda em RTL */
}

/* scroll-snap — rolagem suave com encaixe */
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

/* accent-color — estilizar controles nativos de formulário */
input[type="checkbox"],
input[type="radio"],
input[type="range"] {
  accent-color: var(--color-primary);
}
```

---

## Flexbox vs Grid — Quando Usar Qual

| Cenário | Usar | Por quê |
|---|---|---|
| Barra de navegação | Flexbox | Linha unidimensional com espaçamento |
| Grade de cards | Grid | Bidimensional, linhas de altura igual |
| Layout de formulário | Grid | Labels e inputs alinhados em colunas |
| Centralizar um elemento | Grid | `place-items: center` é o mais curto |
| Sidebar + conteúdo | Grid ou Flexbox | Grid para áreas de template, Flex para divisão simples |
| Lista de cards responsiva | Grid | `auto-fit` + `minmax` resolve tudo |
| Espaço entre itens | Flexbox | `justify-content: space-between` |
| Widgets de dashboard | Grid | Abranger múltiplas linhas/colunas |
| Seções empilhadas verticalmente | Flexbox | Direção coluna com `gap` |
| Layout de página complexo | Grid | Áreas de template para regiões nomeadas |

**Regra prática**: Flexbox para componentes (barras de navegação, botões, layouts pequenos). Grid para layouts de página e tudo que precise de linhas E colunas.

---

## Reset e Estilos Base

Um reset mínimo para renderização consistente entre navegadores.

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

/* Acessibilidade: respeitar as preferências do usuário */
@media (prefers-reduced-motion: reduce) {
  html { scroll-behavior: auto; }
}
```

---

## Referência Rápida

| Propriedade | Flexbox | Grid |
|---|---|---|
| Ativar | `display: flex` | `display: grid` |
| Direção | `flex-direction` | `grid-template-columns/rows` |
| Quebra de linha | `flex-wrap: wrap` | Automático com `auto-fit` |
| Espaçamento | `gap` | `gap` |
| Alinhamento horizontal | `justify-content` | `justify-items` / `justify-content` |
| Alinhamento vertical | `align-items` | `align-items` / `align-content` |
| Dimensionamento de itens | `flex: 1 0 200px` | `minmax(200px, 1fr)` |
| Centralizar tudo | `justify-content + align-items: center` | `place-items: center` |
| Responsivo | `flex-wrap` + media queries | `auto-fit` + `minmax()` |

---

## Fim da Transmissão

Esta cheatsheet cobre as técnicas de layout CSS que alimentam cada site moderno — de centralizar uma div a construir dashboards responsivos complexos. Flexbox para fluxo unidimensional, Grid para layouts bidimensionais e variáveis CSS para sistemas de design sustentáveis. Adicione aos favoritos, consulte em entrevistas frontend e pare de lutar com CSS. O motor de layout agora trabalha para você.
