---
title: "CSS लेआउट चीटशीट: Flexbox और Grid विज़ुअल गाइड"
description: "CSS Flexbox और Grid का निश्चित संदर्भ। div को केंद्रित करना, रेस्पॉन्सिव लेआउट बनाना, मीडिया क्वेरीज़ में महारत हासिल करना, और मॉडर्न CSS वेरिएबल्स का उपयोग कॉपी-पेस्ट उदाहरणों के साथ सीखें।"
date: 2026-02-11
tags: ["css", "cheatsheet", "frontend", "flexbox", "grid", "web-dev"]
keywords: ["css flexbox चीटशीट", "css grid ट्यूटोरियल", "css div केंद्रित करें", "वेब डेवलपमेंट सीखें", "css रेस्पॉन्सिव लेआउट", "मीडिया क्वेरीज़", "css वेरिएबल्स", "फ्रंटएंड इंटरव्यू", "flexbox vs grid", "css लेआउट गाइड", "css grid उदाहरण", "flexbox align items", "css gap प्रॉपर्टी", "मॉडर्न css 2026"]
draft: false
schema_json: >
  {
    "@context": "https://schema.org",
    "@type": "TechArticle",
    "name": "CSS लेआउट चीटशीट: Flexbox और Grid विज़ुअल गाइड",
    "description": "रेस्पॉन्सिव डिज़ाइन पैटर्न और मॉडर्न CSS वेरिएबल्स के साथ CSS Flexbox और Grid लेआउट का संपूर्ण विज़ुअल संदर्भ।",
    "proficiencyLevel": "Intermediate",
    "inLanguage": "hi"
  }
---

## रेंडरिंग इंजन ऑनलाइन

CSS लेआउट वह कौशल है जो बनाने वाले डेवलपर्स को संघर्ष करने वाले डेवलपर्स से अलग करता है। Flexbox एक-आयामी फ्लो संभालता है — रो या कॉलम। Grid दो-आयामी लेआउट संभालता है — रो और कॉलम एक साथ। मिलकर, वे पिछले दशक के हर float हैक, clearfix, और positioning ट्रिक को बदल देते हैं। यह चीटशीट दोनों सिस्टम को प्रोडक्शन-रेडी स्निपेट्स, रेस्पॉन्सिव पैटर्न, और मॉडर्न CSS वेरिएबल्स के साथ कवर करती है। यहाँ हर तकनीक वह है जो फ्रंटएंड इंटरव्यूअर आपसे जानने की उम्मीद करते हैं। कॉपी, पेस्ट, शिप।

---

## Flexbox मूलभूत बातें

Flexbox एक समय में एक दिशा में काम करता है — रो या कॉलम। पैरेंट कंटेनर लेआउट को कंट्रोल करता है; चिल्ड्रेन फ्लेक्स आइटम हैं।

### कंटेनर प्रॉपर्टीज़

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

### आइटम प्रॉपर्टीज़

```css
.item {
  flex-grow: 0;
  flex-grow: 1;
  flex-grow: 2;

  flex-shrink: 1;
  flex-shrink: 0;

  flex-basis: auto;
  flex-basis: 200px;
  flex-basis: 0;

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

## केंद्रित करना — शाश्वत प्रश्न

CSS में कंटेंट को केंद्रित करने की हर विधि, सरल से अचूक तक।

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

## सामान्य Flexbox पैटर्न

### नेवबार

```css
.navbar {
  display: flex;
  justify-content: space-between;
  align-items: center;
  padding: 0 20px;
  height: 60px;
}
.navbar .logo { flex-shrink: 0; }
.navbar .nav-links { display: flex; gap: 20px; list-style: none; }
```

### कार्ड रो (रेस्पॉन्सिव)

```css
.card-row { display: flex; flex-wrap: wrap; gap: 20px; }
.card { flex: 1 1 300px; max-width: 400px; }
```

### स्टिकी फुटर

```css
body { display: flex; flex-direction: column; min-height: 100vh; }
main { flex: 1; }
footer { flex-shrink: 0; }
```

### साइडबार लेआउट

```css
.layout { display: flex; min-height: 100vh; }
.sidebar { flex: 0 0 250px; }
.content { flex: 1; }
```

---

## CSS Grid मूलभूत बातें

Grid दो-आयामी लेआउट बनाता है। रो और कॉलम डिफ़ाइन करें, फिर आइटम्स को ग्रिड सेल्स में रखें।

### कंटेनर प्रॉपर्टीज़

```css
.grid {
  display: grid;

  grid-template-columns: 200px 1fr 200px;
  grid-template-columns: repeat(3, 1fr);
  grid-template-columns: repeat(auto-fill, minmax(250px, 1fr));
  grid-template-columns: repeat(auto-fit, minmax(250px, 1fr));

  grid-template-rows: auto 1fr auto;
  grid-template-rows: repeat(3, 200px);

  grid-auto-rows: minmax(100px, auto);

  gap: 20px;
  gap: 20px 10px;

  justify-items: start | center | end | stretch;
  align-items: start | center | end | stretch;

  justify-content: start | center | end | space-between | space-around;
  align-content: start | center | end | space-between | space-around;

  place-items: center;
  place-content: center;
}
```

### auto-fill बनाम auto-fit

```css
/* auto-fill: create as many columns as fit, leave empty columns */
grid-template-columns: repeat(auto-fill, minmax(200px, 1fr));

/* auto-fit: same as auto-fill, but collapses empty tracks */
grid-template-columns: repeat(auto-fit, minmax(200px, 1fr));
```

### आइटम प्लेसमेंट

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

## Grid टेम्पलेट एरिया

पठनीय, विज़ुअल ग्रिड परिभाषाओं के लिए अपने लेआउट क्षेत्रों को नाम दें।

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

## सामान्य Grid पैटर्न

### रेस्पॉन्सिव कार्ड ग्रिड

```css
.card-grid {
  display: grid;
  grid-template-columns: repeat(auto-fit, minmax(280px, 1fr));
  gap: 24px;
  padding: 24px;
}
```

### डैशबोर्ड लेआउट

```css
.dashboard {
  display: grid;
  grid-template-columns: repeat(4, 1fr);
  grid-auto-rows: minmax(150px, auto);
  gap: 16px;
}
.widget-large { grid-column: span 2; grid-row: span 2; }
.widget-wide { grid-column: span 2; }
```

### इमेज गैलरी (मेसनरी-जैसी)

```css
.gallery {
  display: grid;
  grid-template-columns: repeat(auto-fill, minmax(200px, 1fr));
  grid-auto-rows: 200px;
  gap: 10px;
}
.gallery .featured { grid-column: span 2; grid-row: span 2; }
.gallery img { width: 100%; height: 100%; object-fit: cover; border-radius: 8px; }
```

### होली ग्रेल लेआउट

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

## मीडिया क्वेरीज़

व्यूपोर्ट आकार, यूज़र प्राथमिकताओं, और डिवाइस सुविधाओं पर प्रतिक्रिया दें।

```css
.container { padding: 16px; }

@media (min-width: 768px) {
  .container { padding: 24px; max-width: 720px; margin: 0 auto; }
}

@media (min-width: 1024px) { .container { max-width: 960px; } }
@media (min-width: 1280px) { .container { max-width: 1200px; } }

@media (prefers-color-scheme: dark) {
  :root { --bg: #0a0a0a; --text: #e0e0e0; }
}

@media (prefers-reduced-motion: reduce) {
  * { animation-duration: 0.01ms !important; transition-duration: 0.01ms !important; }
}

@media (hover: hover) { .card:hover { transform: translateY(-4px); } }

@media print { .no-print { display: none; } body { font-size: 12pt; color: #000; } }

.card-container { container-type: inline-size; }
@container (min-width: 400px) { .card { flex-direction: row; } }
```

---

## CSS कस्टम प्रॉपर्टीज़ (वेरिएबल्स)

प्रति संदर्भ ओवरराइड किए जा सकने वाले पुन: प्रयोज्य मान परिभाषित करें। थीम करने योग्य डिज़ाइन सिस्टम की नींव।

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

  --space-xs: 4px; --space-sm: 8px; --space-md: 16px;
  --space-lg: 24px; --space-xl: 48px;

  --radius-sm: 4px; --radius-md: 8px; --radius-lg: 16px;
  --shadow-md: 0 4px 12px rgba(0, 0, 0, 0.3);

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
  --color-bg: #ffffff; --color-surface: #f5f5f5; --color-text: #1a1a1a;
}

.responsive-padding { padding: calc(var(--space-md) + 1vw); }
```

---

## मॉडर्न CSS सुविधाएँ

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

input[type="checkbox"], input[type="radio"], input[type="range"] {
  accent-color: var(--color-primary);
}
```

---

## Flexbox बनाम Grid — कब कौन सा उपयोग करें

| परिदृश्य | उपयोग | क्यों |
|---|---|---|
| नेवबार | Flexbox | स्पेसिंग वाली एक-आयामी रो |
| कार्ड ग्रिड | Grid | दो-आयामी, समान-ऊंचाई वाली रो |
| फॉर्म लेआउट | Grid | कॉलम में संरेखित लेबल और इनपुट |
| एक एलिमेंट केंद्रित करना | Grid | `place-items: center` सबसे छोटा है |
| साइडबार + कंटेंट | Grid या Flexbox | टेम्पलेट एरिया के लिए Grid, सिंपल स्प्लिट के लिए Flex |
| रेस्पॉन्सिव कार्ड लिस्ट | Grid | `auto-fit` + `minmax` सब संभालता है |
| आइटम्स के बीच स्पेस | Flexbox | `justify-content: space-between` |
| डैशबोर्ड विजेट्स | Grid | कई रो/कॉलम में फैलें |
| वर्टिकल स्टैक्ड सेक्शन | Flexbox | `gap` के साथ कॉलम दिशा |
| जटिल पेज लेआउट | Grid | नामित क्षेत्रों के लिए टेम्पलेट एरिया |

**अंगूठे का नियम**: कंपोनेंट्स के लिए Flexbox (नेवबार, बटन, छोटे लेआउट)। पेज-लेवल लेआउट और रो तथा कॉलम दोनों की ज़रूरत वाली चीज़ों के लिए Grid।

---

## रीसेट और बेस स्टाइल्स

सुसंगत क्रॉस-ब्राउज़र रेंडरिंग के लिए न्यूनतम रीसेट।

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

## त्वरित संदर्भ

| प्रॉपर्टी | Flexbox | Grid |
|---|---|---|
| सक्रिय करें | `display: flex` | `display: grid` |
| दिशा | `flex-direction` | `grid-template-columns/rows` |
| रैप | `flex-wrap: wrap` | `auto-fit` के साथ स्वचालित |
| गैप | `gap` | `gap` |
| हॉरिज़ॉन्टल अलाइन | `justify-content` | `justify-items` / `justify-content` |
| वर्टिकल अलाइन | `align-items` | `align-items` / `align-content` |
| आइटम साइज़िंग | `flex: 1 0 200px` | `minmax(200px, 1fr)` |
| पूर्ण केंद्रित | `justify-content + align-items: center` | `place-items: center` |
| रेस्पॉन्सिव | `flex-wrap` + मीडिया क्वेरीज़ | `auto-fit` + `minmax()` |

---

## ट्रांसमिशन समाप्त

यह चीटशीट हर मॉडर्न वेबसाइट को शक्ति देने वाली CSS लेआउट तकनीकों को कवर करती है — div को केंद्रित करने से लेकर जटिल रेस्पॉन्सिव डैशबोर्ड बनाने तक। एक-आयामी फ्लो के लिए Flexbox, दो-आयामी लेआउट के लिए Grid, और रखरखाव योग्य डिज़ाइन सिस्टम के लिए CSS वेरिएबल्स। बुकमार्क करें, फ्रंटएंड इंटरव्यू में संदर्भ लें, और CSS से लड़ना बंद करें। लेआउट इंजन अब आपके लिए काम करता है।
