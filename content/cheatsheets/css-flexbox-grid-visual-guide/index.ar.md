---
title: "ورقة مرجعية لتخطيطات CSS: دليل Flexbox و Grid المرئي"
description: "المرجع النهائي لـ CSS Flexbox و Grid. تعلم توسيط العناصر، بناء التخطيطات المتجاوبة، إتقان استعلامات الوسائط، واستخدام متغيرات CSS الحديثة مع أمثلة جاهزة للنسخ واللصق."
date: 2026-02-11
tags: ["css", "cheatsheet", "frontend", "flexbox", "grid", "web-dev"]
keywords: ["ورقة مرجعية css flexbox", "شرح css grid", "توسيط div css", "تعلم تطوير الويب", "تخطيط متجاوب css", "استعلامات الوسائط", "متغيرات css", "مقابلة الواجهة الأمامية", "flexbox مقابل grid", "دليل تخطيط css", "أمثلة css grid", "flexbox محاذاة العناصر", "خاصية gap css", "css حديث 2026"]
draft: false
schema_json: >
  {
    "@context": "https://schema.org",
    "@type": "TechArticle",
    "name": "ورقة مرجعية لتخطيطات CSS: دليل Flexbox و Grid المرئي",
    "description": "مرجع مرئي شامل لتخطيطات CSS Flexbox و Grid مع أنماط التصميم المتجاوب ومتغيرات CSS الحديثة.",
    "proficiencyLevel": "Intermediate",
    "inLanguage": "ar"
  }
---

## محرك العرض متصل

تخطيط CSS هو المهارة التي تفصل المطورين الذين يبنون عن المطورين الذين يعانون. Flexbox يتعامل مع التدفق أحادي البعد — صفوف أو أعمدة. Grid يتعامل مع التخطيطات ثنائية الأبعاد — صفوف وأعمدة في آن واحد. معاً، يستبدلان كل حيل float و clearfix وتقنيات التموضع من العقد الماضي. تغطي هذه الورقة المرجعية كلا النظامين مع مقتطفات جاهزة للإنتاج، وأنماط متجاوبة، ومتغيرات CSS الحديثة التي تحافظ على قابلية صيانة الكود. كل تقنية هنا هي ما يتوقع محاورو الواجهة الأمامية أن تعرفه. انسخ، الصق، انشر.

---

## أساسيات Flexbox

Flexbox يعمل في اتجاه واحد في كل مرة — صف أو عمود. الحاوية الأم تتحكم في التخطيط؛ العناصر الأبناء هي عناصر Flex.

### خصائص الحاوية

```css
.container {
  display: flex;

  flex-direction: row;
  flex-direction: row-reverse;
  flex-direction: column;
  flex-direction: column-reverse;

  flex-wrap: nowrap;
  flex-wrap: wrap;

  justify-content: flex-start;
  justify-content: flex-end;
  justify-content: center;
  justify-content: space-between;
  justify-content: space-around;
  justify-content: space-evenly;

  align-items: stretch;
  align-items: flex-start;
  align-items: flex-end;
  align-items: center;
  align-items: baseline;

  gap: 20px;
  gap: 20px 10px;
}
```

### خصائص العنصر

```css
.item {
  flex-grow: 0;
  flex-grow: 1;
  flex-shrink: 1;
  flex-shrink: 0;
  flex-basis: auto;
  flex-basis: 200px;

  flex: 1;
  flex: 0 0 300px;
  flex: 1 0 200px;

  align-self: flex-start;
  align-self: center;
  align-self: flex-end;

  order: -1;
  order: 0;
  order: 1;
}
```

---

## التوسيط — السؤال الأبدي

كل طريقة لتوسيط المحتوى في CSS.

```css
.center-flex { display: flex; justify-content: center; align-items: center; min-height: 100vh; }
.center-grid { display: grid; place-items: center; min-height: 100vh; }
.center-margin { width: 300px; margin: 0 auto; }
.center-absolute { position: absolute; top: 50%; left: 50%; transform: translate(-50%, -50%); }
.parent { display: grid; }
.child { margin: auto; }
.center-text { text-align: center; line-height: 100px; }
```

---

## أنماط Flexbox الشائعة

### شريط التنقل

```css
.navbar { display: flex; justify-content: space-between; align-items: center; padding: 0 20px; height: 60px; }
.navbar .logo { flex-shrink: 0; }
.navbar .nav-links { display: flex; gap: 20px; list-style: none; }
```

### صف البطاقات (متجاوب)

```css
.card-row { display: flex; flex-wrap: wrap; gap: 20px; }
.card { flex: 1 1 300px; max-width: 400px; }
```

### تذييل ثابت

```css
body { display: flex; flex-direction: column; min-height: 100vh; }
main { flex: 1; }
footer { flex-shrink: 0; }
```

### تخطيط الشريط الجانبي

```css
.layout { display: flex; min-height: 100vh; }
.sidebar { flex: 0 0 250px; }
.content { flex: 1; }
```

---

## أساسيات CSS Grid

Grid ينشئ تخطيطات ثنائية الأبعاد. حدد الصفوف والأعمدة، ثم ضع العناصر في خلايا الشبكة.

### خصائص الحاوية

```css
.grid {
  display: grid;

  grid-template-columns: 200px 1fr 200px;
  grid-template-columns: repeat(3, 1fr);
  grid-template-columns: repeat(auto-fill, minmax(250px, 1fr));
  grid-template-columns: repeat(auto-fit, minmax(250px, 1fr));

  grid-template-rows: auto 1fr auto;
  grid-auto-rows: minmax(100px, auto);

  gap: 20px;

  justify-items: start | center | end | stretch;
  align-items: start | center | end | stretch;
  justify-content: start | center | end | space-between | space-around;
  align-content: start | center | end | space-between | space-around;

  place-items: center;
  place-content: center;
}
```

### auto-fill مقابل auto-fit

```css
grid-template-columns: repeat(auto-fill, minmax(200px, 1fr));
grid-template-columns: repeat(auto-fit, minmax(200px, 1fr));
```

### وضع العناصر

```css
.item {
  grid-column: 1 / 3;
  grid-column: 1 / -1;
  grid-column: span 2;
  grid-row: 1 / 3;
  grid-row: span 3;
  grid-area: 1 / 1 / 3 / 3;
  justify-self: center;
  align-self: end;
}
```

---

## مناطق قالب Grid

تسمية مناطق التخطيط لتعريفات شبكة مرئية وقابلة للقراءة.

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

@media (max-width: 768px) {
  .layout {
    grid-template-areas: "header" "content" "sidebar" "footer";
    grid-template-columns: 1fr;
    grid-template-rows: auto;
  }
}
```

---

## أنماط Grid الشائعة

### شبكة بطاقات متجاوبة

```css
.card-grid {
  display: grid;
  grid-template-columns: repeat(auto-fit, minmax(280px, 1fr));
  gap: 24px; padding: 24px;
}
```

### تخطيط لوحة التحكم

```css
.dashboard { display: grid; grid-template-columns: repeat(4, 1fr); grid-auto-rows: minmax(150px, auto); gap: 16px; }
.widget-large { grid-column: span 2; grid-row: span 2; }
.widget-wide { grid-column: span 2; }
```

### معرض الصور

```css
.gallery { display: grid; grid-template-columns: repeat(auto-fill, minmax(200px, 1fr)); grid-auto-rows: 200px; gap: 10px; }
.gallery .featured { grid-column: span 2; grid-row: span 2; }
.gallery img { width: 100%; height: 100%; object-fit: cover; border-radius: 8px; }
```

### تخطيط الكأس المقدسة

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

## استعلامات الوسائط

الاستجابة لحجم العرض وتفضيلات المستخدم وميزات الجهاز.

```css
.container { padding: 16px; }
@media (min-width: 768px) { .container { padding: 24px; max-width: 720px; margin: 0 auto; } }
@media (min-width: 1024px) { .container { max-width: 960px; } }
@media (min-width: 1280px) { .container { max-width: 1200px; } }

@media (prefers-color-scheme: dark) { :root { --bg: #0a0a0a; --text: #e0e0e0; } }
@media (prefers-reduced-motion: reduce) { * { animation-duration: 0.01ms !important; transition-duration: 0.01ms !important; } }
@media (hover: hover) { .card:hover { transform: translateY(-4px); } }
@media print { .no-print { display: none; } body { font-size: 12pt; color: #000; } }

.card-container { container-type: inline-size; }
@container (min-width: 400px) { .card { flex-direction: row; } }
```

---

## خصائص CSS المخصصة (المتغيرات)

تعريف قيم قابلة لإعادة الاستخدام يمكن تجاوزها حسب السياق. أساس أنظمة التصميم القابلة للتخصيص.

```css
:root {
  --color-primary: #00e5ff; --color-secondary: #7b1fa2;
  --color-bg: #0a0a0a; --color-surface: #1a1a2e;
  --color-text: #e0e0e0; --color-text-muted: #888;
  --color-success: #00ff41; --color-error: #ff3d3d;

  --font-body: "Inter", -apple-system, sans-serif;
  --font-mono: "Fira Code", "Courier New", monospace;

  --space-xs: 4px; --space-sm: 8px; --space-md: 16px; --space-lg: 24px; --space-xl: 48px;
  --radius-sm: 4px; --radius-md: 8px; --radius-lg: 16px;
  --shadow-md: 0 4px 12px rgba(0, 0, 0, 0.3);
  --transition-fast: 150ms ease; --transition-normal: 300ms ease;
}

.card { background: var(--color-surface); color: var(--color-text); padding: var(--space-lg); border-radius: var(--radius-md); box-shadow: var(--shadow-md); transition: transform var(--transition-normal); }
.element { color: var(--color-accent, #ff6600); }
[data-theme="light"] { --color-bg: #ffffff; --color-surface: #f5f5f5; --color-text: #1a1a1a; }
.responsive-padding { padding: calc(var(--space-md) + 1vw); }
```

---

## ميزات CSS الحديثة

```css
.video-container { aspect-ratio: 16 / 9; width: 100%; }
.avatar { aspect-ratio: 1; border-radius: 50%; }
.title { font-size: clamp(1.5rem, 4vw, 3rem); }
.container { width: clamp(300px, 90%, 1200px); }
.sidebar { width: min(300px, 30%); }
.hero { height: max(400px, 50vh); }
.card :is(h1, h2, h3) { color: white; }
.card:has(img) { padding: 0; }
.form:has(:invalid) .submit { opacity: 0.5; }
.element { margin-inline-start: 20px; padding-block: 10px; border-inline-end: 1px solid; }
.carousel { display: flex; overflow-x: auto; scroll-snap-type: x mandatory; gap: 16px; }
.carousel > * { scroll-snap-align: start; flex: 0 0 300px; }
input[type="checkbox"], input[type="radio"], input[type="range"] { accent-color: var(--color-primary); }
```

---

## Flexbox مقابل Grid — متى تستخدم أيهما

| السيناريو | الاستخدام | السبب |
|---|---|---|
| شريط التنقل | Flexbox | صف أحادي البعد مع تباعد |
| شبكة البطاقات | Grid | ثنائي الأبعاد، صفوف متساوية الارتفاع |
| تخطيط النماذج | Grid | تسميات ومدخلات متحاذية في أعمدة |
| توسيط عنصر واحد | Grid | `place-items: center` هو الأقصر |
| شريط جانبي + محتوى | Grid أو Flexbox | Grid لمناطق القالب، Flex للتقسيم البسيط |
| قائمة بطاقات متجاوبة | Grid | `auto-fit` + `minmax` يتعامل مع كل شيء |
| المسافة بين العناصر | Flexbox | `justify-content: space-between` |
| عناصر لوحة التحكم | Grid | تمتد عبر عدة صفوف/أعمدة |
| أقسام مكدسة عمودياً | Flexbox | اتجاه العمود مع `gap` |
| تخطيط صفحة معقد | Grid | مناطق القالب للمناطق المسماة |

**قاعدة عامة**: Flexbox للمكونات (أشرطة التنقل، الأزرار، التخطيطات الصغيرة). Grid للتخطيطات على مستوى الصفحة وأي شيء يحتاج صفوفاً وأعمدة.

---

## إعادة التعيين والأنماط الأساسية

إعادة تعيين مصغرة لعرض متسق عبر المتصفحات.

```css
*, *::before, *::after { box-sizing: border-box; margin: 0; padding: 0; }
html { font-size: 16px; -webkit-text-size-adjust: 100%; scroll-behavior: smooth; }
body { font-family: var(--font-body); line-height: 1.6; color: var(--color-text); background: var(--color-bg); -webkit-font-smoothing: antialiased; }
img, video, svg { display: block; max-width: 100%; height: auto; }
a { color: inherit; text-decoration: none; }
button { font: inherit; cursor: pointer; border: none; background: none; }
ul, ol { list-style: none; }
@media (prefers-reduced-motion: reduce) { html { scroll-behavior: auto; } }
```

---

## مرجع سريع

| الخاصية | Flexbox | Grid |
|---|---|---|
| التفعيل | `display: flex` | `display: grid` |
| الاتجاه | `flex-direction` | `grid-template-columns/rows` |
| الالتفاف | `flex-wrap: wrap` | تلقائي مع `auto-fit` |
| الفجوة | `gap` | `gap` |
| المحاذاة الأفقية | `justify-content` | `justify-items` / `justify-content` |
| المحاذاة العمودية | `align-items` | `align-items` / `align-content` |
| حجم العنصر | `flex: 1 0 200px` | `minmax(200px, 1fr)` |
| توسيط كامل | `justify-content + align-items: center` | `place-items: center` |
| متجاوب | `flex-wrap` + استعلامات الوسائط | `auto-fit` + `minmax()` |

---

## انتهى الإرسال

تغطي هذه الورقة المرجعية تقنيات تخطيط CSS التي تشغل كل موقع ويب حديث — من توسيط div إلى بناء لوحات تحكم متجاوبة معقدة. Flexbox للتدفق أحادي البعد، Grid للتخطيطات ثنائية الأبعاد، ومتغيرات CSS لأنظمة تصميم قابلة للصيانة. احفظها، ارجع إليها في مقابلات الواجهة الأمامية، وتوقف عن محاربة CSS. محرك التخطيط يعمل لصالحك الآن.
