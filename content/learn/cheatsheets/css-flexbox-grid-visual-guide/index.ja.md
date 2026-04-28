---
title: "CSS レイアウト チートシート：Flexbox & Grid ビジュアルガイド"
description: "決定版 CSS Flexbox と Grid リファレンス。div の中央配置、レスポンシブレイアウトの構築、メディアクエリの習得、モダン CSS 変数の使用を、コピペ可能な例で学びましょう。"
date: 2026-02-10
tags: ["css", "cheatsheet", "frontend", "flexbox", "grid", "web-dev"]
keywords: ["css flexbox チートシート", "css grid チュートリアル", "css 中央配置 div", "ウェブ開発 学習", "css レスポンシブレイアウト", "メディアクエリ", "css 変数", "フロントエンド 面接", "flexbox vs grid", "css レイアウトガイド", "css grid 例", "flexbox align items", "css gap プロパティ", "モダン css 2026"]
draft: false
schema_json: >
  {
    "@context": "https://schema.org",
    "@type": "TechArticle",
    "name": "CSS レイアウト チートシート：Flexbox & Grid ビジュアルガイド",
    "description": "レスポンシブデザインパターンとモダン CSS 変数を含む CSS Flexbox と Grid レイアウトの完全ビジュアルリファレンス。",
    "proficiencyLevel": "Intermediate",
    "inLanguage": "ja"
  }
---

## レンダリングエンジン起動

CSS レイアウトは、構築できる開発者と苦労する開発者を分ける技術です。Flexbox は一次元のフロー（行または列）を処理します。Grid は二次元レイアウト（行と列を同時に）を処理します。これらを組み合わせることで、過去10年間のすべての float ハック、clearfix、ポジショニングトリックを置き換えます。このチートシートは、本番環境対応のスニペット、レスポンシブパターン、コードを保守しやすくするモダン CSS 変数で両方のシステムをカバーしています。ここにあるすべてのテクニックは、フロントエンド面接官があなたに知っていてほしいものです。コピー、ペースト、デプロイ。

---

## Flexbox の基本

Flexbox は一度に一方向で動作します——行または列のいずれか。親コンテナがレイアウトを制御し、子要素がフレックスアイテムです。

### コンテナプロパティ

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

### アイテムプロパティ

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

## 中央配置——永遠の課題

CSS でコンテンツを中央に配置するすべての方法。シンプルなものから確実なものまで。

```css
/* ✅ Method 1: Flexbox (most common) */
.center-flex {
  display: flex;
  justify-content: center;
  align-items: center;
  min-height: 100vh;
}

/* ✅ Method 2: Grid (shortest) */
.center-grid {
  display: grid;
  place-items: center;
  min-height: 100vh;
}

/* ✅ Method 3: Margin auto (block element) */
.center-margin {
  width: 300px;
  margin: 0 auto;
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
.child { margin: auto; }

/* ✅ Center text */
.center-text {
  text-align: center;
  line-height: 100px;
}
```

---

## よくある Flexbox パターン

### ナビゲーションバー

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

### カード行（レスポンシブ）

```css
.card-row {
  display: flex;
  flex-wrap: wrap;
  gap: 20px;
}
.card {
  flex: 1 1 300px;
  max-width: 400px;
}
```

### スティッキーフッター

```css
body {
  display: flex;
  flex-direction: column;
  min-height: 100vh;
}
main {
  flex: 1;
}
footer {
  flex-shrink: 0;
}
```

### サイドバーレイアウト

```css
.layout {
  display: flex;
  min-height: 100vh;
}
.sidebar {
  flex: 0 0 250px;
}
.content {
  flex: 1;
}
```

---

## CSS Grid の基本

Grid は二次元レイアウトを作成します。行と列を定義し、アイテムをグリッドセルに配置します。

### コンテナプロパティ

```css
.grid {
  display: grid;

  /* Define columns */
  grid-template-columns: 200px 1fr 200px;
  grid-template-columns: repeat(3, 1fr);
  grid-template-columns: repeat(auto-fill, minmax(250px, 1fr));
  grid-template-columns: repeat(auto-fit, minmax(250px, 1fr));

  /* Define rows */
  grid-template-rows: auto 1fr auto;
  grid-template-rows: repeat(3, 200px);

  /* Auto rows (for dynamic content) */
  grid-auto-rows: minmax(100px, auto);

  /* Gap between cells */
  gap: 20px;
  gap: 20px 10px;

  /* Alignment of ALL items within their cells */
  justify-items: start | center | end | stretch;
  align-items: start | center | end | stretch;

  /* Alignment of the GRID within the container */
  justify-content: start | center | end | space-between | space-around;
  align-content: start | center | end | space-between | space-around;

  /* Shorthand: align + justify */
  place-items: center;
  place-content: center;
}
```

### auto-fill と auto-fit

```css
/* auto-fill: create as many columns as fit, leave empty columns */
grid-template-columns: repeat(auto-fill, minmax(200px, 1fr));

/* auto-fit: same as auto-fill, but collapses empty tracks */
grid-template-columns: repeat(auto-fit, minmax(200px, 1fr));
```

### アイテム配置

```css
.item {
  grid-column: 1 / 3;
  grid-column: 1 / -1;
  grid-column: span 2;

  grid-row: 1 / 3;
  grid-row: span 3;

  grid-column: 2;
  grid-row: 1;

  grid-area: 1 / 1 / 3 / 3;

  justify-self: center;
  align-self: end;
}
```

---

## Grid テンプレートエリア

レイアウト領域に名前を付けて、読みやすい視覚的なグリッド定義を実現。

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

## よくある Grid パターン

### レスポンシブカードグリッド

```css
.card-grid {
  display: grid;
  grid-template-columns: repeat(auto-fit, minmax(280px, 1fr));
  gap: 24px;
  padding: 24px;
}
```

### ダッシュボードレイアウト

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

### 画像ギャラリー（メイソンリー風）

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

### ホーリーグレイルレイアウト

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

## メディアクエリ

ビューポートサイズ、ユーザー設定、デバイス機能に応答します。

```css
/* Mobile-first approach (recommended) */
.container { padding: 16px; }

@media (min-width: 768px) {
  .container { padding: 24px; max-width: 720px; margin: 0 auto; }
}

@media (min-width: 1024px) {
  .container { max-width: 960px; }
}

@media (min-width: 1280px) {
  .container { max-width: 1200px; }
}

/* Dark mode detection */
@media (prefers-color-scheme: dark) {
  :root { --bg: #0a0a0a; --text: #e0e0e0; }
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
.card-container { container-type: inline-size; }
@container (min-width: 400px) {
  .card { flex-direction: row; }
}
```

---

## CSS カスタムプロパティ（変数）

コンテキストごとにオーバーライドできる再利用可能な値を定義。テーマ対応デザインシステムの基盤。

```css
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

.card {
  background: var(--color-surface);
  color: var(--color-text);
  padding: var(--space-lg);
  border-radius: var(--radius-md);
  box-shadow: var(--shadow-md);
  font-family: var(--font-body);
  transition: transform var(--transition-normal);
}

.element { color: var(--color-accent, #ff6600); }

[data-theme="light"] {
  --color-bg: #ffffff;
  --color-surface: #f5f5f5;
  --color-text: #1a1a1a;
}

.card-danger { --color-primary: var(--color-error); }

.responsive-padding { padding: calc(var(--space-md) + 1vw); }

@media (max-width: 768px) {
  :root { --font-size-xl: 1.5rem; --space-lg: 16px; }
}
```

---

## モダン CSS 機能

```css
.video-container { aspect-ratio: 16 / 9; width: 100%; }
.avatar { aspect-ratio: 1; border-radius: 50%; }

.title { font-size: clamp(1.5rem, 4vw, 3rem); }
.container { width: clamp(300px, 90%, 1200px); }
.card { padding: clamp(16px, 3vw, 48px); }

.sidebar { width: min(300px, 30%); }
.hero { height: max(400px, 50vh); }

.card :is(h1, h2, h3) { color: white; }

.card:has(img) { padding: 0; }
.form:has(:invalid) .submit { opacity: 0.5; }
.nav:has(.dropdown:hover) { background: #111; }

.element {
  margin-inline-start: 20px;
  padding-block: 10px;
  border-inline-end: 1px solid;
}

.carousel {
  display: flex;
  overflow-x: auto;
  scroll-snap-type: x mandatory;
  gap: 16px;
}
.carousel > * { scroll-snap-align: start; flex: 0 0 300px; }

input[type="checkbox"],
input[type="radio"],
input[type="range"] {
  accent-color: var(--color-primary);
}
```

---

## Flexbox vs Grid — いつどちらを使うか

| シナリオ | 使用 | 理由 |
|---|---|---|
| ナビバー | Flexbox | 間隔のある一次元の行 |
| カードグリッド | Grid | 二次元、等しい高さの行 |
| フォームレイアウト | Grid | 列で揃えたラベルと入力欄 |
| 要素の中央配置 | Grid | `place-items: center` が最短 |
| サイドバー + コンテンツ | Grid または Flexbox | テンプレートエリアなら Grid、シンプルな分割なら Flex |
| レスポンシブカードリスト | Grid | `auto-fit` + `minmax` がすべて処理 |
| アイテム間のスペース | Flexbox | `justify-content: space-between` |
| ダッシュボードウィジェット | Grid | 複数の行/列にまたがる |
| 垂直積み重ねセクション | Flexbox | `gap` 付きの列方向 |
| 複雑なページレイアウト | Grid | 名前付き領域のテンプレートエリア |

**経験則**：Flexbox はコンポーネント用（ナビバー、ボタン、小さなレイアウト）。Grid はページレベルのレイアウトと行と列の両方が必要なものに。

---

## リセット & ベーススタイル

一貫したクロスブラウザレンダリングのための最小限のリセット。

```css
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

img, video, svg { display: block; max-width: 100%; height: auto; }
a { color: inherit; text-decoration: none; }
button { font: inherit; cursor: pointer; border: none; background: none; }
ul, ol { list-style: none; }

@media (prefers-reduced-motion: reduce) {
  html { scroll-behavior: auto; }
}
```

---

## クイックリファレンス

| プロパティ | Flexbox | Grid |
|---|---|---|
| 有効化 | `display: flex` | `display: grid` |
| 方向 | `flex-direction` | `grid-template-columns/rows` |
| ラップ | `flex-wrap: wrap` | `auto-fit` で自動 |
| 間隔 | `gap` | `gap` |
| 水平揃え | `justify-content` | `justify-items` / `justify-content` |
| 垂直揃え | `align-items` | `align-items` / `align-content` |
| アイテムサイズ | `flex: 1 0 200px` | `minmax(200px, 1fr)` |
| 完全中央配置 | `justify-content + align-items: center` | `place-items: center` |
| レスポンシブ | `flex-wrap` + メディアクエリ | `auto-fit` + `minmax()` |

---

## 送信完了

このチートシートは、div の中央配置から複雑なレスポンシブダッシュボードの構築まで、あらゆるモダン Web サイトを支える CSS レイアウト技術をカバーしています。一次元フローには Flexbox、二次元レイアウトには Grid、保守性の高いデザインシステムには CSS 変数。ブックマークして、フロントエンド面接で参照し、CSS と戦うのをやめましょう。レイアウトエンジンはあなたのために働きます。
