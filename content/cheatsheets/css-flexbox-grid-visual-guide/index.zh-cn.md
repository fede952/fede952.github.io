---
title: "CSS 布局速查表：Flexbox 与 Grid 可视化指南"
description: "权威的 CSS Flexbox 和 Grid 参考手册。学习居中 div、构建响应式布局、掌握媒体查询，以及使用现代 CSS 变量，附带可复制粘贴的示例。"
date: 2026-02-10
tags: ["css", "cheatsheet", "frontend", "flexbox", "grid", "web-dev"]
keywords: ["css flexbox 速查表", "css grid 教程", "css 居中 div", "学习前端开发", "css 响应式布局", "媒体查询", "css 变量", "前端面试", "flexbox vs grid", "css 布局指南", "css grid 示例", "flexbox align items", "css gap 属性", "现代 css 2026"]
draft: false
schema_json: >
  {
    "@context": "https://schema.org",
    "@type": "TechArticle",
    "name": "CSS 布局速查表：Flexbox 与 Grid 可视化指南",
    "description": "包含响应式设计模式和现代 CSS 变量的完整 CSS Flexbox 和 Grid 布局可视化参考。",
    "proficiencyLevel": "Intermediate",
    "inLanguage": "zh-cn"
  }
---

## 渲染引擎就绪

CSS 布局是区分能够构建页面的开发者和苦苦挣扎的开发者的技能。Flexbox 处理一维流——行或列。Grid 处理二维布局——同时处理行和列。它们一起替代了过去十年的所有浮动技巧、清除浮动和定位技巧。这份速查表用生产级代码片段、响应式模式和保持代码可维护的现代 CSS 变量来覆盖两个系统。这里的每项技术都是前端面试官期望你掌握的。复制、粘贴、发布。

---

## Flexbox 基础

Flexbox 每次只在一个方向上工作——行或列。父容器控制布局；子元素是弹性项目。

### 容器属性

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

### 项目属性

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

## 居中——永恒的问题

CSS 中居中内容的每种方法，从简单到万无一失。

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

## 常见 Flexbox 模式

### 导航栏

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

### 卡片行（响应式）

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

### 粘性页脚

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

### 侧边栏布局

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

## CSS Grid 基础

Grid 创建二维布局。定义行和列，然后将项目放入网格单元格中。

### 容器属性

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

### auto-fill 与 auto-fit

```css
/* auto-fill: create as many columns as fit, leave empty columns */
grid-template-columns: repeat(auto-fill, minmax(200px, 1fr));
/* With 3 items in a 1000px container: creates 5 tracks, 2 empty */

/* auto-fit: same as auto-fill, but collapses empty tracks */
grid-template-columns: repeat(auto-fit, minmax(200px, 1fr));
/* With 3 items in a 1000px container: items stretch to fill */
```

### 项目放置

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

## Grid 模板区域

为布局区域命名，实现可读的可视化网格定义。

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

## 常见 Grid 模式

### 响应式卡片网格

```css
.card-grid {
  display: grid;
  grid-template-columns: repeat(auto-fit, minmax(280px, 1fr));
  gap: 24px;
  padding: 24px;
}
/* Cards automatically wrap to new rows as the viewport shrinks */
```

### 仪表盘布局

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

### 图片画廊（瀑布流风格）

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

### 圣杯布局

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

## 媒体查询

响应视口大小、用户偏好和设备功能。

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

## CSS 自定义属性（变量）

定义可按上下文覆盖的可重用值。主题化设计系统的基础。

```css
/* Define on :root for global access */
:root {
  --color-primary: #00e5ff;
  --color-secondary: #7b1fa2;
  --color-bg: #0a0a0a;
  --color-surface: #1a1a2e;
  --color-text: #e0e0e0;
  --color-text-muted: #888;
  --color-success: #00ff41;
  --color-error: #ff3d3d;

  --font-body: "Inter", -apple-system, sans-serif;
  --font-mono: "Fira Code", "Courier New", monospace;
  --font-size-sm: 0.875rem;
  --font-size-md: 1rem;
  --font-size-lg: 1.25rem;
  --font-size-xl: 2rem;

  --space-xs: 4px;
  --space-sm: 8px;
  --space-md: 16px;
  --space-lg: 24px;
  --space-xl: 48px;

  --radius-sm: 4px;
  --radius-md: 8px;
  --radius-lg: 16px;
  --shadow-sm: 0 1px 3px rgba(0, 0, 0, 0.2);
  --shadow-md: 0 4px 12px rgba(0, 0, 0, 0.3);
  --shadow-lg: 0 10px 30px rgba(0, 0, 0, 0.5);

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
  color: var(--color-accent, #ff6600);
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

## 现代 CSS 特性

```css
/* aspect-ratio — maintain proportions */
.video-container {
  aspect-ratio: 16 / 9;
  width: 100%;
}
.avatar {
  aspect-ratio: 1;
  border-radius: 50%;
}

/* clamp() — responsive values without media queries */
.title {
  font-size: clamp(1.5rem, 4vw, 3rem);
}
.container {
  width: clamp(300px, 90%, 1200px);
}
.card {
  padding: clamp(16px, 3vw, 48px);
}

/* min() and max() */
.sidebar {
  width: min(300px, 30%);
}
.hero {
  height: max(400px, 50vh);
}

/* :is() and :where() — reduce selector repetition */
.card :is(h1, h2, h3) { color: white; }

/* :has() — parent selector (game changer) */
.card:has(img) { padding: 0; }
.form:has(:invalid) .submit { opacity: 0.5; }
.nav:has(.dropdown:hover) { background: #111; }

/* Logical properties (RTL support) */
.element {
  margin-inline-start: 20px;
  padding-block: 10px;
  border-inline-end: 1px solid;
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

## Flexbox vs Grid——何时使用哪个

| 场景 | 使用 | 原因 |
|---|---|---|
| 导航栏 | Flexbox | 带间距的一维行 |
| 卡片网格 | Grid | 二维、等高行 |
| 表单布局 | Grid | 列中对齐的标签和输入框 |
| 居中单个元素 | Grid | `place-items: center` 最简短 |
| 侧边栏 + 内容 | Grid 或 Flexbox | Grid 用于模板区域，Flex 用于简单分割 |
| 响应式卡片列表 | Grid | `auto-fit` + `minmax` 处理一切 |
| 项目间间距 | Flexbox | `justify-content: space-between` |
| 仪表盘小部件 | Grid | 跨越多行/多列 |
| 垂直堆叠区域 | Flexbox | 带 `gap` 的列方向 |
| 复杂页面布局 | Grid | 命名区域的模板区域 |

**经验法则**：Flexbox 用于组件（导航栏、按钮、小布局）。Grid 用于页面级布局和需要行和列的任何内容。

---

## 重置和基础样式

用于一致跨浏览器渲染的最小化重置。

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

## 快速参考

| 属性 | Flexbox | Grid |
|---|---|---|
| 激活 | `display: flex` | `display: grid` |
| 方向 | `flex-direction` | `grid-template-columns/rows` |
| 换行 | `flex-wrap: wrap` | 使用 `auto-fit` 自动换行 |
| 间距 | `gap` | `gap` |
| 水平对齐 | `justify-content` | `justify-items` / `justify-content` |
| 垂直对齐 | `align-items` | `align-items` / `align-content` |
| 项目尺寸 | `flex: 1 0 200px` | `minmax(200px, 1fr)` |
| 完全居中 | `justify-content + align-items: center` | `place-items: center` |
| 响应式 | `flex-wrap` + 媒体查询 | `auto-fit` + `minmax()` |

---

## 传输结束

这份速查表涵盖了驱动每个现代网站的 CSS 布局技术——从居中一个 div 到构建复杂的响应式仪表盘。Flexbox 用于一维流，Grid 用于二维布局，CSS 变量用于可维护的设计系统。收藏它，在前端面试中参考它，不再和 CSS 较劲。布局引擎现在为你工作。
