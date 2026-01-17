# 🏗️ ARCHITETTURA - Federico Sella Tech Portal

**Documento di Architettura Tecnica**
**Data**: 17 Gennaio 2026
**Versione**: 1.0
**Autore**: Tech Lead Analysis

---

## 📊 EXECUTIVE SUMMARY

Questo documento descrive l'architettura attuale del sito personale di Federico Sella e propone una roadmap di evoluzione verso un **Tech Portal Professionale** con News automatizzate, Tools interattivi e supporto multi-lingua completo.

**Obiettivo**: Trasformare il portfolio statico in una piattaforma dinamica mantenendo la compatibilità con GitHub Pages e i vantaggi di un generatore statico.

---

## 🔍 ANALISI SITUAZIONE ATTUALE

### Stack Tecnologico Identificato

```
Framework:      Hugo (Static Site Generator)
Tema:           PaperMod (git submodule)
Hosting:        GitHub Pages
CI/CD:          GitHub Actions (hugo.yaml)
Lingue:         Inglese (default) + Italiano
Build:          Automatico su push a main
Domain:         federicosella.com (via CNAME)
```

### Struttura Directory Attuale

```
federicosella-site-test/
│
├── .github/
│   └── workflows/
│       └── hugo.yaml              # CI/CD pipeline
│
├── archetypes/                     # Template per nuovi contenuti
├── assets/
│   └── css/
│       └── extended/               # CSS personalizzati per PaperMod
│
├── content/                        # ⭐ Contenuti principali
│   ├── about/
│   │   ├── index.md               # Pagina About (EN)
│   │   └── index.it.md            # Pagina About (IT)
│   │
│   ├── posts/                      # Blog posts (attualmente vuoto)
│   │
│   ├── projects/                   # Progetti personali
│   │   ├── _index.md              # Index progetti (EN)
│   │   ├── _index.it.md           # Index progetti (IT)
│   │   ├── penta-framework/
│   │   ├── lyric-video-generator/
│   │   └── doc/
│   │
│   └── writeups/                   # CTF Writeups
│       ├── _index.md
│       ├── _index.it.md
│       └── htb-cap/
│
├── data/                           # File di dati (vuoto)
├── i18n/                           # Traduzioni (vuoto - usa config)
│
├── layouts/                        # Override template Hugo
│   ├── partials/
│   │   ├── header.html            # Header personalizzato
│   │   └── extend_footer.html     # Footer esteso
│   │
│   └── shortcodes/                 # Componenti riutilizzabili
│       ├── exercise-python.html   # Embedding esercizi Python
│       └── exercise-java.html     # Embedding esercizi Java
│
├── static/                         # File statici serviti as-is
│   ├── favicon.png
│   ├── exercises/                  # File HTML interattivi
│   └── images/
│       ├── logo.jpg
│       ├── profile.jpg
│       ├── projects/
│       └── writeups/
│
├── themes/
│   └── PaperMod/                   # Tema principale (submodule)
│
├── hugo.toml                       # Configurazione Hugo
├── CNAME                           # Domain configuration
└── README.md
```

### Configurazione Multi-Lingua Attuale

**Punti di forza identificati**:
- ✅ Già configurato supporto EN/IT in `hugo.toml`
- ✅ Struttura file `.md` / `.it.md` funzionante
- ✅ Menu separati per lingua con traduzioni
- ✅ Language switcher integrato in PaperMod

**Esempio configurazione** (`hugo.toml:52-90`):
```toml
[languages.en]
  languageName = "English"
  weight = 1

[languages.it]
  languageName = "Italiano"
  weight = 2
```

### Assets e Risorse Identificati

**CSS**:
- `assets/css/extended/` - Personalizzazioni PaperMod (SCSS)

**JavaScript**:
- Nessun file JS custom rilevato (solo tema PaperMod)

**Immagini**:
- `static/images/logo.jpg` - Branding principale
- `static/favicon.png` - Favicon sito
- `static/images/projects/` - Screenshot progetti
- `static/images/writeups/` - Screenshot CTF

**HTML Interattivi**:
- `static/exercises/` - Esercizi di programmazione embedded
- Shortcodes per embedding: `exercise-python.html`, `exercise-java.html`

---

## 🎯 OBIETTIVI TRASFORMAZIONE

### 1. News Automatizzate
- Feed RSS/Atom aggregati da fonti tech (GitHub, HackerNews, CVE)
- Sistema di categorizzazione automatica
- Archivio per data e topic
- Possibile integrazione GitHub Actions per fetch automatico

### 2. Tools Interattivi
- Calcolatori, converter, playground di codice
- Embedding di tool HTML/JS standalone
- Possibile integrazione con API esterne

### 3. Games Section
- Browser games (HTML5 Canvas / WebGL)
- Leaderboard (possibile Netlify Functions o GitHub API)
- Categoria "Retro Gaming", "CTF Challenges"

### 4. Multi-Lingua Scalabile
- Estendere EN/IT a tutte le nuove sezioni
- Template automatici per duplicazione contenuti
- Sistema di fallback lingua

---

## 🏛️ ARCHITETTURA PROPOSTA

### Nuova Struttura Directory (FASE 1)

```
federicosella-site-test/
│
├── content/
│   ├── about/                      # ✅ ESISTENTE - da mantenere
│   │
│   ├── news/                       # 🆕 NUOVA SEZIONE
│   │   ├── _index.md              # Landing page News (EN)
│   │   ├── _index.it.md           # Landing page News (IT)
│   │   ├── 2026/                  # Organizzazione per anno
│   │   │   ├── 01/                # Organizzazione per mese
│   │   │   │   ├── article-1.md
│   │   │   │   └── article-1.it.md
│   │   │   └── 02/
│   │   └── categories/            # Tassonomia personalizzata
│   │       ├── cybersecurity/
│   │       ├── ai-ml/
│   │       └── dev-tools/
│   │
│   ├── tools/                      # 🆕 NUOVA SEZIONE
│   │   ├── _index.md              # Landing page Tools
│   │   ├── _index.it.md
│   │   ├── base64-converter/      # Tool esempio
│   │   │   ├── index.md           # Descrizione tool
│   │   │   └── tool.html          # Logica interattiva
│   │   ├── jwt-decoder/
│   │   └── hash-calculator/
│   │
│   ├── games/                      # 🆕 NUOVA SEZIONE
│   │   ├── _index.md
│   │   ├── _index.it.md
│   │   ├── snake-js/              # Game esempio
│   │   │   ├── index.md           # Descrizione
│   │   │   └── game.html          # Canvas game
│   │   └── ctf-challenges/
│   │
│   ├── projects/                   # ✅ ESISTENTE - da mantenere
│   │   └── [struttura attuale]
│   │
│   ├── writeups/                   # ✅ ESISTENTE - da mantenere
│   │   └── [struttura attuale]
│   │
│   └── posts/                      # ✅ ESISTENTE - blog tradizionale
│       └── [da popolare in futuro]
│
├── static/
│   ├── images/                     # ✅ Ristrutturato
│   │   ├── branding/              # 🆕 logo, favicon
│   │   ├── news/                  # 🆕 immagini articoli news
│   │   ├── tools/                 # 🆕 screenshot tools
│   │   ├── games/                 # 🆕 cover games
│   │   ├── projects/              # ✅ Esistente
│   │   └── writeups/              # ✅ Esistente
│   │
│   ├── js/                         # 🆕 NUOVA - JavaScript custom
│   │   ├── tools/                 # Script per tools interattivi
│   │   │   ├── base64.js
│   │   │   └── jwt-decoder.js
│   │   └── games/                 # Engine games
│   │       └── snake.js
│   │
│   ├── css/                        # 🆕 NUOVA - CSS standalone
│   │   ├── tools.css              # Stili per tools
│   │   └── games.css              # Stili per games
│   │
│   └── exercises/                  # ✅ Esistente - da mantenere
│
├── layouts/
│   ├── _default/
│   │   ├── news.html              # 🆕 Template per news
│   │   ├── tool.html              # 🆕 Template per tools
│   │   └── game.html              # 🆕 Template per games
│   │
│   ├── partials/
│   │   ├── header.html            # ✅ Esistente
│   │   ├── extend_footer.html     # ✅ Esistente
│   │   ├── news-card.html         # 🆕 Card per articoli news
│   │   └── tool-embed.html        # 🆕 Embedding tools
│   │
│   └── shortcodes/
│       ├── exercise-python.html   # ✅ Esistente
│       ├── exercise-java.html     # ✅ Esistente
│       ├── tool-embed.html        # 🆕 Shortcode tool interattivo
│       └── game-embed.html        # 🆕 Shortcode game
│
├── data/
│   ├── news-sources.json          # 🆕 Configurazione feed RSS
│   └── tools-metadata.json        # 🆕 Metadata tools
│
└── scripts/                        # 🆕 NUOVA - Automazioni
    ├── fetch-news.py              # Script aggregazione news
    └── build-tools.sh             # Build tools interattivi
```

### Aggiornamento Menu Navigazione

**File da modificare**: `hugo.toml` (linee 55-90)

```toml
[languages.en.menu]
  [[languages.en.menu.main]]
    identifier = "about"
    name = "About Me"
    url = "/about/"
    weight = 10

  [[languages.en.menu.main]]
    identifier = "news"          # 🆕
    name = "Tech News"           # 🆕
    url = "/news/"               # 🆕
    weight = 15                  # 🆕

  [[languages.en.menu.main]]
    identifier = "tools"         # 🆕
    name = "Tools"               # 🆕
    url = "/tools/"              # 🆕
    weight = 25                  # 🆕

  [[languages.en.menu.main]]
    identifier = "games"         # 🆕
    name = "Games"               # 🆕
    url = "/games/"              # 🆕
    weight = 35                  # 🆕

  [[languages.en.menu.main]]
    identifier = "writeups"
    name = "CTF Writeups"
    url = "/writeups/"
    weight = 40                  # Aggiornato peso

  [[languages.en.menu.main]]
    identifier = "projects"
    name = "Projects"
    url = "/projects/"
    weight = 50                  # Aggiornato peso

# Replica identica per [languages.it.menu] con traduzioni IT
```

---

## 🤖 AUTOMAZIONE NEWS (Proposta Tecnica)

### Approccio 1: GitHub Actions + RSS Feed Aggregator

**Vantaggi**:
- Completamente serverless
- Gratuito con GitHub Actions
- Nessuna infrastruttura esterna

**Workflow proposto** (`.github/workflows/fetch-news.yaml`):

```yaml
name: Fetch Tech News

on:
  schedule:
    - cron: '0 8 * * *'  # Ogni giorno alle 8:00 UTC
  workflow_dispatch:      # Trigger manuale

jobs:
  fetch-news:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4

      - name: Setup Python
        uses: actions/setup-python@v5
        with:
          python-version: '3.11'

      - name: Install dependencies
        run: pip install feedparser pyyaml

      - name: Fetch RSS feeds
        run: python scripts/fetch-news.py

      - name: Commit new articles
        run: |
          git config user.name "News Bot"
          git config user.email "bot@federicosella.com"
          git add content/news/
          git commit -m "🤖 Auto-fetch tech news $(date +%Y-%m-%d)" || exit 0
          git push
```

**Script Python** (`scripts/fetch-news.py`):

```python
import feedparser
import yaml
from datetime import datetime

FEEDS = [
    "https://hnrss.org/frontpage",
    "https://www.reddit.com/r/netsec/.rss",
    "https://feeds.feedburner.com/TheHackersNews"
]

def fetch_and_convert():
    for feed_url in FEEDS:
        feed = feedparser.parse(feed_url)
        for entry in feed.entries[:5]:  # Top 5 articoli
            create_markdown(entry)

def create_markdown(entry):
    date = datetime.now()
    filepath = f"content/news/{date.year}/{date.month:02d}/{entry.id}.md"

    frontmatter = f"""---
title: "{entry.title}"
date: {date.isoformat()}
source: "{entry.link}"
tags: ["Auto-Generated"]
draft: false
---

{entry.summary}

[Read More]({entry.link})
"""
    # Salva file...
```

### Approccio 2: Netlify CMS + Editorial Workflow

Se in futuro si migra da GitHub Pages a Netlify:
- UI web per editing news
- Preview branches automatiche
- Approvazione editoriale

---

## 🛠️ TOOLS INTERATTIVI (Architettura)

### Struttura Tool Tipo

**Directory**: `content/tools/base64-converter/`

**File `index.md`** (SEO + Descrizione):
```markdown
---
title: "Base64 Encoder/Decoder"
description: "Convert text to/from Base64 encoding"
type: "tool"
layout: "tool"
---

Encode and decode Base64 strings directly in your browser.
No data is sent to any server.
```

**File `tool.html`** (Logica interattiva):
```html
<div class="tool-container">
  <textarea id="input" placeholder="Enter text..."></textarea>
  <button onclick="encode()">Encode</button>
  <button onclick="decode()">Decode</button>
  <textarea id="output" readonly></textarea>
</div>

<script src="/js/tools/base64.js"></script>
```

**File `/static/js/tools/base64.js`**:
```javascript
function encode() {
  const input = document.getElementById('input').value;
  document.getElementById('output').value = btoa(input);
}

function decode() {
  const input = document.getElementById('input').value;
  try {
    document.getElementById('output').value = atob(input);
  } catch(e) {
    alert('Invalid Base64 string');
  }
}
```

### Template Hugo (`layouts/_default/tool.html`):

```html
{{ define "main" }}
<article class="tool-page">
  <h1>{{ .Title }}</h1>
  <div class="tool-description">
    {{ .Content }}
  </div>

  <div class="tool-interactive">
    {{ .Params.tool_embed | safeHTML }}
  </div>
</article>
{{ end }}
```

---

## 🎮 GAMES SECTION (Architettura)

### Organizzazione Proposta

**Categorie**:
1. **Browser Games** - HTML5 Canvas (Snake, Pong, Space Invaders clones)
2. **CTF Challenges** - Wargames interattivi (XSS playground, SQL injection lab)
3. **Puzzle Games** - Sudoku solver, Cipher decoder

### Esempio: Snake Game

**Directory**: `content/games/snake-js/`

**File `index.md`**:
```markdown
---
title: "Classic Snake Game"
date: 2026-01-20
description: "Play the classic Snake game in your browser"
game_file: "/games/snake/game.html"
tags: ["HTML5", "Canvas", "Retro"]
---

Classic Snake game built with vanilla JavaScript and HTML5 Canvas.
```

**File `/static/games/snake/game.html`**:
```html
<!DOCTYPE html>
<html>
<head>
  <title>Snake Game</title>
  <style>
    canvas { border: 1px solid #000; background: #000; }
  </style>
</head>
<body>
  <canvas id="gameCanvas" width="400" height="400"></canvas>
  <script src="/js/games/snake.js"></script>
</body>
</html>
```

**Shortcode Hugo** (`layouts/shortcodes/game-embed.html`):
```html
<div class="game-container">
  <iframe src="{{ .Get "src" }}"
          width="{{ .Get "width" | default "800" }}"
          height="{{ .Get "height" | default "600" }}"
          frameborder="0">
  </iframe>
</div>
```

**Utilizzo in Markdown**:
```markdown
{{< game-embed src="/games/snake/game.html" width="600" height="600" >}}
```

---

## 📱 COMPATIBILITÀ GITHUB PAGES

### Limitazioni da Considerare

✅ **Supportato**:
- Siti statici generati (HTML/CSS/JS)
- Hugo build automatico via GitHub Actions
- Custom domain (CNAME)
- HTTPS automatico via Let's Encrypt

❌ **NON Supportato**:
- Server-side rendering (SSR)
- Backend API (Node.js, Python)
- Database dinamici
- WebSockets persistenti

### Soluzioni Alternative per Funzionalità Dinamiche

| Funzionalità | Soluzione GitHub Pages Compatible |
|--------------|-----------------------------------|
| **Form Contact** | Formspree, Google Forms embed |
| **Comments** | Giscus (GitHub Discussions), Utterances |
| **Search** | Lunr.js (client-side), Algolia DocSearch |
| **Analytics** | Google Analytics, Plausible (script) |
| **Leaderboard Games** | GitHub API + GitHub Pages JSON |
| **News Fetching** | GitHub Actions (pre-build) |

---

## 🔄 PIANO DI MIGRAZIONE (Phased Approach)

### FASE 1: Setup Infrastruttura (Sprint 1-2)
- [x] Analisi architettura esistente
- [ ] Creare struttura directory `/news`, `/tools`, `/games`
- [ ] Aggiornare `hugo.toml` con nuovi menu
- [ ] Configurare taxonomies per categorie news
- [ ] Creare template base Hugo per nuove sezioni

### FASE 2: News System (Sprint 3-4)
- [ ] Implementare GitHub Action per RSS fetching
- [ ] Creare script Python `fetch-news.py`
- [ ] Definire fonti RSS in `data/news-sources.json`
- [ ] Creare layout `news.html` e `news-card.html`
- [ ] Test automazione e commit automatici
- [ ] Traduzione italiana articoli (opzionale: API OpenAI)

### FASE 3: Tools Interattivi (Sprint 5-6)
- [ ] Sviluppare primo tool: Base64 Converter
- [ ] Creare template riutilizzabile `tool.html`
- [ ] Implementare shortcode `tool-embed`
- [ ] Aggiungere 3-5 tools essenziali:
  - JWT Decoder
  - Hash Calculator (MD5/SHA256)
  - URL Encoder/Decoder
  - JSON Formatter
  - Regex Tester
- [ ] Mobile responsiveness testing

### FASE 4: Games Section (Sprint 7-8)
- [ ] Sviluppare Snake game (HTML5 Canvas)
- [ ] Creare template `game.html`
- [ ] Implementare shortcode `game-embed`
- [ ] Aggiungere 2-3 games:
  - Classic Pong
  - Memory Card Game
  - CTF Challenge: XSS Playground
- [ ] Leaderboard statico (JSON file)

### FASE 5: Polish & SEO (Sprint 9-10)
- [ ] Ottimizzazione SEO per nuove sezioni
- [ ] Sitemap automatico Hugo
- [ ] Open Graph tags per social sharing
- [ ] Performance audit (Lighthouse)
- [ ] Accessibility check (WCAG 2.1)
- [ ] Cross-browser testing

---

## 🎨 DESIGN SYSTEM (PaperMod Extensions)

### Custom CSS da Implementare

**File**: `assets/css/extended/custom.css` (da creare)

```css
/* News Section */
.news-card {
  border: 1px solid var(--border);
  border-radius: 8px;
  padding: 1.5rem;
  transition: transform 0.2s;
}

.news-card:hover {
  transform: translateY(-4px);
  box-shadow: 0 4px 12px rgba(0,0,0,0.1);
}

/* Tools Section */
.tool-container {
  background: var(--code-bg);
  border-radius: 8px;
  padding: 2rem;
  margin: 2rem 0;
}

.tool-container textarea {
  width: 100%;
  min-height: 150px;
  font-family: 'JetBrains Mono', monospace;
  background: var(--entry);
  border: 1px solid var(--border);
  border-radius: 4px;
  padding: 1rem;
  color: var(--content);
}

/* Games Section */
.game-container {
  display: flex;
  justify-content: center;
  margin: 2rem 0;
}

.game-container iframe {
  border: 2px solid var(--border);
  border-radius: 8px;
  box-shadow: 0 8px 24px rgba(0,0,0,0.2);
}

/* Mobile Responsive */
@media (max-width: 768px) {
  .news-card {
    padding: 1rem;
  }

  .tool-container {
    padding: 1rem;
  }

  .game-container iframe {
    width: 100%;
    height: auto;
  }
}
```

---

## 🔐 SECURITY CONSIDERATIONS

### Content Security Policy (CSP)

Per tools e games con JavaScript custom, configurare CSP headers:

**File**: `static/_headers` (per Netlify) o configurazione server

```
/*
  Content-Security-Policy: default-src 'self'; script-src 'self' 'unsafe-inline'; style-src 'self' 'unsafe-inline'; img-src 'self' https://github.com data:; connect-src 'self'
  X-Frame-Options: SAMEORIGIN
  X-Content-Type-Options: nosniff
  Referrer-Policy: strict-origin-when-cross-origin
```

### Input Sanitization

Per tools che accettano input utente:
- Usare DOMPurify per sanitizzazione HTML
- Validazione client-side per tutti i form
- Nessun `eval()` o `Function()` nei tools

---

## 📊 PERFORMANCE TARGETS

### Metriche Lighthouse (Target)

| Metrica | Target | Note |
|---------|--------|------|
| Performance | >90 | Lazy loading immagini |
| Accessibility | >95 | ARIA labels, contrasto colori |
| Best Practices | >90 | HTTPS, no console errors |
| SEO | >95 | Meta tags, structured data |

### Ottimizzazioni Pianificate

1. **Immagini**: WebP con fallback PNG/JPG
2. **JavaScript**: Minification + tree shaking
3. **CSS**: Critical CSS inline, resto async
4. **Fonts**: Subset fonts, `font-display: swap`
5. **Caching**: Service Worker per offline (opzionale)

---

## 🧪 TESTING STRATEGY

### Pre-Deploy Checklist

- [ ] Hugo build senza errori/warning
- [ ] Test multi-lingua (EN/IT) per tutte le sezioni
- [ ] Responsive design check (mobile/tablet/desktop)
- [ ] Cross-browser testing (Chrome, Firefox, Safari, Edge)
- [ ] Link checker (no broken links)
- [ ] Spell check contenuti
- [ ] Performance audit
- [ ] Accessibility audit

### Continuous Integration

GitHub Actions workflow da aggiungere:

```yaml
name: Quality Checks

on: [push, pull_request]

jobs:
  test:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4

      - name: Setup Hugo
        uses: peaceiris/actions-hugo@v2
        with:
          hugo-version: 'latest'
          extended: true

      - name: Build
        run: hugo --minify

      - name: HTML Validation
        uses: Cyb3r-Jak3/html5validator-action@v7
        with:
          root: public/

      - name: Link Checker
        uses: lycheeverse/lychee-action@v1
        with:
          args: --verbose --no-progress 'public/**/*.html'
```

---

## 📈 ANALYTICS & MONITORING

### Metriche da Tracciare

1. **Traffic**:
   - Pageviews per sezione (news/tools/games)
   - Bounce rate per tipo contenuto
   - Geographic distribution

2. **Engagement**:
   - Tempo medio su tools interattivi
   - Click-through rate su articoli news
   - Partite completate sui games

3. **Technical**:
   - Core Web Vitals (LCP, FID, CLS)
   - Error rate JavaScript
   - Build time Hugo

### Tool Consigliati

- **Google Analytics 4**: Free, completo
- **Plausible Analytics**: Privacy-focused alternative
- **Cloudflare Analytics**: Se si usa Cloudflare CDN

---

## 🚀 DEPLOYMENT WORKFLOW

### Current (GitHub Pages)

```
git push origin main
  ↓
GitHub Actions triggered
  ↓
Hugo build (hugo --minify)
  ↓
Deploy to gh-pages branch
  ↓
GitHub Pages serves static files
  ↓
Live at federicosella.com
```

### Enhanced (con News Automation)

```
Scheduled Cron (daily 8:00 UTC)
  ↓
fetch-news.py eseguito
  ↓
Nuovi articoli committati
  ↓
GitHub Actions triggered
  ↓
Hugo build con nuovi contenuti
  ↓
Deploy automatico
  ↓
News aggiornate live
```

---

## 🔮 ROADMAP FUTURA (Post-Launch)

### Q2 2026
- [ ] Newsletter subscription (via Substack embed)
- [ ] Dark/Light theme toggle (già parzialmente in PaperMod)
- [ ] Search functionality (Lunr.js)
- [ ] RSS feed per sezione news
- [ ] Commenti con Giscus

### Q3 2026
- [ ] API documentation section
- [ ] Code playground integrato (CodeMirror)
- [ ] Tutorial interattivi
- [ ] Podcast/Video section

### Q4 2026
- [ ] Migrazione a Netlify/Vercel (valutare)
- [ ] Serverless functions per features avanzate
- [ ] Headless CMS (Decap CMS)
- [ ] Progressive Web App (PWA)

---

## 🤝 CONTRIBUZIONI & MAINTENANCE

### Repository Structure

Mantenere separazione:
- `main` branch → Production (auto-deploy)
- `dev` branch → Development/testing
- Feature branches → `feature/news-system`, `feature/tools-section`

### Commit Convention

```
feat: Add Base64 converter tool
fix: Correct Italian translation in About page
docs: Update ARCHITECTURE.md
chore: Bump Hugo version to 0.122
```

---

## 📚 RISORSE & RIFERIMENTI

### Documentazione

- [Hugo Documentation](https://gohugo.io/documentation/)
- [PaperMod Theme Wiki](https://github.com/adityatelange/hugo-PaperMod/wiki)
- [GitHub Pages Docs](https://docs.github.com/en/pages)
- [GitHub Actions Docs](https://docs.github.com/en/actions)

### Tool & Librerie Consigliate

| Categoria | Tool | Uso |
|-----------|------|-----|
| RSS Parsing | `feedparser` (Python) | News aggregation |
| HTML Sanitization | DOMPurify | XSS prevention tools |
| Code Highlighting | Prism.js / Highlight.js | Code blocks |
| Icons | Font Awesome / Feather Icons | UI elements |
| Charts | Chart.js | Statistiche news/games |

---

## ✅ NEXT STEPS

### Immediate Actions (da fare ora)

1. **Review questo documento** con il team/stakeholder
2. **Approvazione architettura** proposta
3. **Setup repository branches** (dev/main)
4. **Creazione Issue su GitHub** per tracking FASE 1
5. **Kickoff Sprint 1** - Inizio implementazione

### Decision Points

❓ **Domande da chiarire**:
- Quali fonti RSS prioritizzare per news?
- Quali tools implementare per primi (top 5)?
- Serve leaderboard persistente per games o solo client-side?
- Budget per eventuali servizi esterni (Formspree, Algolia)?

---

## 📞 CONTATTI PROGETTO

**Tech Lead**: Claude (AI Assistant)
**Owner**: Federico Sella
**Repository**: https://github.com/fede952/fede952.github.io
**Live Site**: https://www.federicosella.com

---

**Documento Versione**: 1.0
**Ultima Modifica**: 2026-01-17
**Status**: ✅ Ready for Review
