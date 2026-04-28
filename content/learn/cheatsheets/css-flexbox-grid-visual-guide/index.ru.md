---
title: "Шпаргалка по CSS-раскладкам: Визуальное руководство по Flexbox и Grid"
description: "Полный справочник по CSS Flexbox и Grid. Научитесь центрировать div, создавать адаптивные макеты, освойте медиа-запросы и используйте современные CSS-переменные с готовыми примерами для копирования."
date: 2026-02-10
tags: ["css", "cheatsheet", "frontend", "flexbox", "grid", "web-dev"]
keywords: ["шпаргалка css flexbox", "руководство css grid", "центрирование div css", "обучение веб-разработке", "адаптивная раскладка css", "медиа-запросы", "css переменные", "собеседование фронтенд", "flexbox против grid", "руководство по css раскладке", "примеры css grid", "flexbox align items", "свойство css gap", "современный css 2026"]
draft: false
schema_json: >
  {
    "@context": "https://schema.org",
    "@type": "TechArticle",
    "name": "Шпаргалка по CSS-раскладкам: Визуальное руководство по Flexbox и Grid",
    "description": "Полный визуальный справочник по CSS Flexbox и Grid с паттернами адаптивного дизайна и современными CSS-переменными.",
    "proficiencyLevel": "Intermediate",
    "inLanguage": "ru"
  }
---

## Движок рендеринга запущен

CSS-раскладка — это навык, который отличает разработчиков, которые создают, от разработчиков, которые борются с кодом. Flexbox управляет одномерным потоком — строками или столбцами. Grid управляет двумерными раскладками — строками И столбцами одновременно. Вместе они заменяют все хаки с float, clearfix и трюки с позиционированием последнего десятилетия. Эта шпаргалка охватывает обе системы с готовыми к продакшену фрагментами, адаптивными паттернами и современными CSS-переменными, которые делают ваш код поддерживаемым. Все техники здесь — то, что от вас ожидают на собеседованиях по фронтенду. Копируйте, вставляйте, деплойте.

---

## Основы Flexbox

Flexbox работает в одном направлении за раз — либо строка, либо столбец. Родительский контейнер управляет раскладкой; дочерние элементы — это flex-элементы.

### Свойства контейнера

```css
.container {
  display: flex;            /* Активировать flexbox */

  /* Направление: как располагаются элементы */
  flex-direction: row;             /* → слева направо (по умолчанию) */
  flex-direction: row-reverse;     /* ← справа налево */
  flex-direction: column;          /* ↓ сверху вниз */
  flex-direction: column-reverse;  /* ↑ снизу вверх */

  /* Перенос: что происходит при переполнении */
  flex-wrap: nowrap;   /* Одна строка, элементы сжимаются (по умолчанию) */
  flex-wrap: wrap;     /* Элементы переносятся на следующую строку */

  /* Выравнивание по главной оси (направление потока) */
  justify-content: flex-start;     /* Упаковка в начало |||....... */
  justify-content: flex-end;       /* Упаковка в конец  .......|||*/
  justify-content: center;         /* По центру         ...||| ...*/
  justify-content: space-between;  /* Первый и последний по краям |..|..|*/
  justify-content: space-around;   /* Равное пространство вокруг  .|..|..|.*/
  justify-content: space-evenly;   /* Равное пространство между   .|..|..|.*/

  /* Выравнивание по поперечной оси (перпендикулярно потоку) */
  align-items: stretch;      /* Заполнить высоту контейнера (по умолчанию) */
  align-items: flex-start;   /* Выровнять по верху */
  align-items: flex-end;     /* Выровнять по низу */
  align-items: center;       /* Центрировать вертикально */
  align-items: baseline;     /* Выровнять по базовой линии текста */

  /* Промежуток между элементами (современная замена margin) */
  gap: 20px;            /* Равный промежуток в обоих направлениях */
  gap: 20px 10px;       /* row-gap column-gap */
}
```

### Свойства элементов

```css
.item {
  /* Рост: сколько дополнительного пространства занимает элемент */
  flex-grow: 0;   /* Не растёт (по умолчанию) */
  flex-grow: 1;   /* Занимает равную долю дополнительного пространства */
  flex-grow: 2;   /* Занимает двойную долю */

  /* Сжатие: насколько элемент сжимается при нехватке места */
  flex-shrink: 1;   /* Сжимается равномерно (по умолчанию) */
  flex-shrink: 0;   /* Никогда не сжимается (сохраняет оригинальный размер) */

  /* Базис: начальный размер до растяжения/сжатия */
  flex-basis: auto;   /* Использовать размер контента (по умолчанию) */
  flex-basis: 200px;  /* Начать с 200px */
  flex-basis: 0;      /* Игнорировать размер контента, распределить всё пространство */

  /* Сокращённая запись: grow shrink basis */
  flex: 1;          /* flex: 1 1 0 — расти равномерно, игнорировать контент */
  flex: 0 0 300px;  /* Фиксированные 300px, без роста, без сжатия */
  flex: 1 0 200px;  /* Начать с 200px, может расти, никогда не сжимается */

  /* Переопределить выравнивание по поперечной оси только для этого элемента */
  align-self: flex-start;
  align-self: center;
  align-self: flex-end;

  /* Визуальная переупорядочивание (не меняет порядок в DOM) */
  order: -1;  /* Переместить перед элементами по умолчанию */
  order: 0;   /* По умолчанию */
  order: 1;   /* Переместить после элементов по умолчанию */
}
```

---

## Центрирование — Вечный вопрос

Все способы центрирования контента в CSS, от простого до надёжного.

```css
/* ✅ Способ 1: Flexbox (самый распространённый) */
.center-flex {
  display: flex;
  justify-content: center;  /* горизонтально */
  align-items: center;      /* вертикально */
  min-height: 100vh;
}

/* ✅ Способ 2: Grid (самый короткий) */
.center-grid {
  display: grid;
  place-items: center;      /* горизонтально + вертикально в одной строке */
  min-height: 100vh;
}

/* ✅ Способ 3: Margin auto (блочный элемент) */
.center-margin {
  width: 300px;
  margin: 0 auto;           /* только горизонтально */
}

/* ✅ Способ 4: Absolute + Transform (поддержка устаревших браузеров) */
.center-absolute {
  position: absolute;
  top: 50%;
  left: 50%;
  transform: translate(-50%, -50%);
}

/* ✅ Способ 5: Grid + margin auto (один дочерний элемент) */
.parent { display: grid; }
.child { margin: auto; }    /* центрирует по обеим осям */

/* ✅ Центрирование текста */
.center-text {
  text-align: center;            /* текст по горизонтали */
  line-height: 100px;            /* по вертикали (одна строка, известная высота) */
}
```

---

## Распространённые паттерны Flexbox

### Навигационная панель

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

### Ряд карточек (адаптивный)

```css
.card-row {
  display: flex;
  flex-wrap: wrap;
  gap: 20px;
}
.card {
  flex: 1 1 300px;  /* растёт, сжимается, минимум 300px */
  max-width: 400px;
}
```

### Прилипающий футер

```css
body {
  display: flex;
  flex-direction: column;
  min-height: 100vh;
}
main {
  flex: 1;  /* main растёт, чтобы оттолкнуть футер вниз */
}
footer {
  flex-shrink: 0;
}
```

### Раскладка с боковой панелью

```css
.layout {
  display: flex;
  min-height: 100vh;
}
.sidebar {
  flex: 0 0 250px;  /* фиксированная ширина 250px */
}
.content {
  flex: 1;          /* занимает оставшееся пространство */
}
```

---

## Основы CSS Grid

Grid создаёт двумерные раскладки. Определите строки и столбцы, затем размещайте элементы в ячейках сетки.

### Свойства контейнера

```css
.grid {
  display: grid;

  /* Определить столбцы */
  grid-template-columns: 200px 1fr 200px;       /* фиксированный | гибкий | фиксированный */
  grid-template-columns: repeat(3, 1fr);          /* 3 равных столбца */
  grid-template-columns: repeat(auto-fill, minmax(250px, 1fr)); /* адаптивный */
  grid-template-columns: repeat(auto-fit, minmax(250px, 1fr));  /* адаптивный, растягивающийся */

  /* Определить строки */
  grid-template-rows: auto 1fr auto;       /* шапка | контент | подвал */
  grid-template-rows: repeat(3, 200px);    /* 3 строки по 200px */

  /* Автоматические строки (для динамического контента) */
  grid-auto-rows: minmax(100px, auto);     /* минимум 100px, растёт по необходимости */

  /* Промежуток между ячейками */
  gap: 20px;            /* равный в обоих направлениях */
  gap: 20px 10px;       /* row-gap column-gap */

  /* Выравнивание ВСЕХ элементов внутри их ячеек */
  justify-items: start | center | end | stretch;
  align-items: start | center | end | stretch;

  /* Выравнивание СЕТКИ внутри контейнера */
  justify-content: start | center | end | space-between | space-around;
  align-content: start | center | end | space-between | space-around;

  /* Сокращённая запись: align + justify */
  place-items: center;         /* обе оси */
  place-content: center;       /* обе оси */
}
```

### auto-fill и auto-fit

```css
/* auto-fill: создать столько столбцов, сколько поместится, оставить пустые столбцы */
grid-template-columns: repeat(auto-fill, minmax(200px, 1fr));
/* С 3 элементами в контейнере 1000px: создаёт 5 дорожек, 2 пустые */

/* auto-fit: то же, что auto-fill, но сворачивает пустые дорожки */
grid-template-columns: repeat(auto-fit, minmax(200px, 1fr));
/* С 3 элементами в контейнере 1000px: элементы растягиваются для заполнения */
```

### Размещение элементов

```css
.item {
  /* Занять определённые столбцы */
  grid-column: 1 / 3;        /* начало на линии 1, конец на линии 3 (занимает 2) */
  grid-column: 1 / -1;       /* занять ВСЕ столбцы (полная ширина) */
  grid-column: span 2;       /* занять 2 столбца от текущей позиции */

  /* Занять определённые строки */
  grid-row: 1 / 3;           /* начало на линии 1, конец на линии 3 */
  grid-row: span 3;          /* занять 3 строки */

  /* Разместить в точной ячейке */
  grid-column: 2;
  grid-row: 1;

  /* Сокращённая запись: row-start / col-start / row-end / col-end */
  grid-area: 1 / 1 / 3 / 3;  /* верхний левый блок 2x2 */

  /* Переопределить выравнивание для этого элемента */
  justify-self: center;
  align-self: end;
}
```

---

## Именованные области Grid

Дайте имена регионам раскладки для читаемых визуальных определений сетки.

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

/* Адаптивность: стек на мобильных */
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

## Распространённые паттерны Grid

### Адаптивная сетка карточек

```css
.card-grid {
  display: grid;
  grid-template-columns: repeat(auto-fit, minmax(280px, 1fr));
  gap: 24px;
  padding: 24px;
}
/* Карточки автоматически переносятся на новые строки при уменьшении области просмотра */
```

### Раскладка панели управления

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

### Галерея изображений (типа Masonry)

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

### Раскладка «Святой Грааль»

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

## Медиа-запросы

Реагируйте на размер области просмотра, пользовательские предпочтения и возможности устройства.

```css
/* Подход mobile-first (рекомендуется) */
/* Базовые стили = мобильные */
.container { padding: 16px; }

/* Планшеты и выше */
@media (min-width: 768px) {
  .container { padding: 24px; max-width: 720px; margin: 0 auto; }
}

/* Десктоп и выше */
@media (min-width: 1024px) {
  .container { max-width: 960px; }
}

/* Большой десктоп */
@media (min-width: 1280px) {
  .container { max-width: 1200px; }
}

/* Распространённые контрольные точки */
/* 480px  — маленькие телефоны */
/* 768px  — планшеты */
/* 1024px — маленькие десктопы */
/* 1280px — большие десктопы */
/* 1536px — очень большие экраны */

/* Обнаружение тёмной темы */
@media (prefers-color-scheme: dark) {
  :root {
    --bg: #0a0a0a;
    --text: #e0e0e0;
  }
}

/* Уменьшенное движение (доступность) */
@media (prefers-reduced-motion: reduce) {
  * {
    animation-duration: 0.01ms !important;
    transition-duration: 0.01ms !important;
  }
}

/* Возможность наведения (сенсорный экран или мышь) */
@media (hover: hover) {
  .card:hover { transform: translateY(-4px); }
}

/* Стили для печати */
@media print {
  .no-print { display: none; }
  body { font-size: 12pt; color: #000; }
}

/* Контейнерные запросы (современный CSS) */
.card-container {
  container-type: inline-size;
}
@container (min-width: 400px) {
  .card { flex-direction: row; }
}
```

---

## Пользовательские свойства CSS (переменные)

Определяйте многоразовые значения, которые можно переопределять в зависимости от контекста. Основа тематических дизайн-систем.

```css
/* Определить на :root для глобального доступа */
:root {
  /* Цвета */
  --color-primary: #00e5ff;
  --color-secondary: #7b1fa2;
  --color-bg: #0a0a0a;
  --color-surface: #1a1a2e;
  --color-text: #e0e0e0;
  --color-text-muted: #888;
  --color-success: #00ff41;
  --color-error: #ff3d3d;

  /* Типографика */
  --font-body: "Inter", -apple-system, sans-serif;
  --font-mono: "Fira Code", "Courier New", monospace;
  --font-size-sm: 0.875rem;
  --font-size-md: 1rem;
  --font-size-lg: 1.25rem;
  --font-size-xl: 2rem;

  /* Шкала отступов */
  --space-xs: 4px;
  --space-sm: 8px;
  --space-md: 16px;
  --space-lg: 24px;
  --space-xl: 48px;

  /* Рамки и тени */
  --radius-sm: 4px;
  --radius-md: 8px;
  --radius-lg: 16px;
  --shadow-sm: 0 1px 3px rgba(0, 0, 0, 0.2);
  --shadow-md: 0 4px 12px rgba(0, 0, 0, 0.3);
  --shadow-lg: 0 10px 30px rgba(0, 0, 0, 0.5);

  /* Переходы */
  --transition-fast: 150ms ease;
  --transition-normal: 300ms ease;
}

/* Использование */
.card {
  background: var(--color-surface);
  color: var(--color-text);
  padding: var(--space-lg);
  border-radius: var(--radius-md);
  box-shadow: var(--shadow-md);
  font-family: var(--font-body);
  transition: transform var(--transition-normal);
}

/* Резервные значения */
.element {
  color: var(--color-accent, #ff6600); /* использует #ff6600, если --color-accent не определён */
}

/* Переопределение в контексте (темизация) */
[data-theme="light"] {
  --color-bg: #ffffff;
  --color-surface: #f5f5f5;
  --color-text: #1a1a1a;
}

/* Переопределение в компоненте */
.card-danger {
  --color-primary: var(--color-error);
}

/* Динамические значения с calc() */
.responsive-padding {
  padding: calc(var(--space-md) + 1vw);
}

/* Переменные в медиа-запросах */
@media (max-width: 768px) {
  :root {
    --font-size-xl: 1.5rem;
    --space-lg: 16px;
  }
}
```

---

## Современные возможности CSS

```css
/* aspect-ratio — сохранение пропорций */
.video-container {
  aspect-ratio: 16 / 9;
  width: 100%;
}
.avatar {
  aspect-ratio: 1;       /* идеальный квадрат */
  border-radius: 50%;
}

/* clamp() — адаптивные значения без медиа-запросов */
.title {
  font-size: clamp(1.5rem, 4vw, 3rem);  /* мин, предпочтительный, макс */
}
.container {
  width: clamp(300px, 90%, 1200px);
}
.card {
  padding: clamp(16px, 3vw, 48px);
}

/* min() и max() */
.sidebar {
  width: min(300px, 30%);   /* то, что меньше */
}
.hero {
  height: max(400px, 50vh); /* то, что больше */
}

/* :is() и :where() — уменьшение повторения селекторов */
/* До: */
.card h1, .card h2, .card h3 { color: white; }
/* После: */
.card :is(h1, h2, h3) { color: white; }

/* :has() — родительский селектор (революция) */
.card:has(img) { padding: 0; }                     /* карточка, содержащая изображение */
.form:has(:invalid) .submit { opacity: 0.5; }      /* форма с невалидными полями */
.nav:has(.dropdown:hover) { background: #111; }    /* навигация при наведении на выпадающее меню */

/* Логические свойства (поддержка RTL) */
.element {
  margin-inline-start: 20px;   /* left в LTR, right в RTL */
  padding-block: 10px;          /* top + bottom */
  border-inline-end: 1px solid; /* right в LTR, left в RTL */
}

/* scroll-snap — плавная привязка прокрутки */
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

/* accent-color — стилизация нативных элементов форм */
input[type="checkbox"],
input[type="radio"],
input[type="range"] {
  accent-color: var(--color-primary);
}
```

---

## Flexbox и Grid — Когда что использовать

| Сценарий | Использовать | Почему |
|---|---|---|
| Навигационная панель | Flexbox | Одномерная строка с промежутками |
| Сетка карточек | Grid | Двумерная, строки одинаковой высоты |
| Раскладка формы | Grid | Выровненные метки и поля в столбцах |
| Центрирование одного элемента | Grid | `place-items: center` — самый короткий способ |
| Боковая панель + контент | Grid или Flexbox | Grid для именованных областей, Flex для простого разделения |
| Адаптивный список карточек | Grid | `auto-fit` + `minmax` справляется со всем |
| Расстояние между элементами | Flexbox | `justify-content: space-between` |
| Виджеты панели управления | Grid | Занимают несколько строк/столбцов |
| Вертикально расположенные секции | Flexbox | Направление column с `gap` |
| Сложная раскладка страницы | Grid | Именованные области для регионов |

**Правило большого пальца**: Flexbox для компонентов (навигация, кнопки, маленькие раскладки). Grid для раскладок уровня страницы и всего, что требует строк И столбцов.

---

## Сброс и базовые стили

Минимальный сброс для единообразного отображения в разных браузерах.

```css
/* Современный CSS-сброс */
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

/* Доступность: уважение пользовательских предпочтений */
@media (prefers-reduced-motion: reduce) {
  html { scroll-behavior: auto; }
}
```

---

## Краткий справочник

| Свойство | Flexbox | Grid |
|---|---|---|
| Активация | `display: flex` | `display: grid` |
| Направление | `flex-direction` | `grid-template-columns/rows` |
| Перенос | `flex-wrap: wrap` | Автоматический с `auto-fit` |
| Промежуток | `gap` | `gap` |
| Горизонтальное выравнивание | `justify-content` | `justify-items` / `justify-content` |
| Вертикальное выравнивание | `align-items` | `align-items` / `align-content` |
| Размер элемента | `flex: 1 0 200px` | `minmax(200px, 1fr)` |
| Центрировать всё | `justify-content + align-items: center` | `place-items: center` |
| Адаптивность | `flex-wrap` + медиа-запросы | `auto-fit` + `minmax()` |

---

## Конец передачи

Эта шпаргалка охватывает техники CSS-раскладки, которые лежат в основе каждого современного веб-сайта — от центрирования div до создания сложных адаптивных панелей управления. Flexbox для одномерного потока, Grid для двумерных раскладок и CSS-переменные для поддерживаемых дизайн-систем. Сохраните в закладки, используйте как справочник на собеседованиях по фронтенду и перестаньте бороться с CSS. Движок раскладки теперь работает на вас.
