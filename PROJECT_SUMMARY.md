# PROJECT SUMMARY — Federico Sella Suite

> **Generated:** 2026-02-03
> **Repository:** `https://github.com/fede952/fede952.github.io`
> **Live Site:** `https://federicosella.com/`

---

## 1. File Tree

```
federicosella-site/
├── .github/workflows/
│   ├── daily_news.yml
│   └── hugo.yaml
├── archetypes/
│   └── default.md
├── assets/css/extended/
│   ├── custom.css
│   └── home-grid.css
├── content/
│   ├── about/                          # About Me page (12 languages)
│   ├── games/
│   │   ├── deploy-on-friday/           # Endless runner game (12 langs)
│   │   ├── example-game/               # Game template
│   │   └── sudo-type/                  # Typing defense game (12 langs)
│   ├── guides/
│   │   ├── deepseek-vs-chatgpt/        # LLM comparison guide (12 langs)
│   │   └── local-ai-setup-ollama/      # Local AI setup guide (12 langs)
│   ├── news/
│   │   └── 2026/
│   │       ├── 01/                     # ~400 news articles (EN + IT)
│   │       └── 02/                     # February 2026 articles
│   ├── posts/                          # Blog posts
│   ├── projects/
│   │   ├── doc/                        # Portfolio project
│   │   ├── lyric-video-generator/      # FLAC lyric video tool
│   │   ├── penta-framework/            # Pentesting framework
│   │   └── zendesk-soc-hunter/         # Browser extension for SOC
│   ├── tools/
│   │   ├── base64-converter/           # Base64 encode/decode (12 langs)
│   │   ├── caesar-cipher/              # Caesar cipher (12 langs)
│   │   ├── easy-cron/                  # Visual cron builder
│   │   ├── example-tool/               # Tool template
│   │   ├── freelance-calculator/       # Hourly rate calculator
│   │   ├── glitch-forge/               # Glitch art generator
│   │   ├── hash-generator/             # Crypto hash generator (12 langs)
│   │   ├── netguard/                   # IP leak & fingerprint test
│   │   ├── pass-fort/                  # Password generator & auditor
│   │   ├── password-generator/         # Legacy password gen
│   │   ├── pixel-shrink/               # Image compressor (9 langs)
│   │   ├── reflex-grid/                # Aim trainer game
│   │   └── zen-focus/                  # Pomodoro & ambient noise
│   └── writeups/
│       └── htb-cap/                    # HackTheBox writeup
├── layouts/
│   ├── _default/
│   │   ├── game.html
│   │   ├── home.html
│   │   ├── news.html
│   │   ├── single.html
│   │   ├── tool.html
│   │   └── tool-split.html
│   ├── games/single.html
│   ├── news/single.html
│   ├── partials/
│   │   ├── extend_footer.html
│   │   ├── extend_head.html
│   │   ├── google_analytics.html
│   │   ├── header.html
│   │   ├── index_profile.html
│   │   ├── news-card.html
│   │   ├── share_icons.html
│   │   ├── share-buttons.html
│   │   └── tool-embed.html
│   ├── projects/single.html
│   ├── shortcodes/
│   │   ├── ad-banner.html
│   │   ├── exercise-java.html
│   │   ├── exercise-python.html
│   │   ├── game-embed.html
│   │   ├── password-gen.html
│   │   └── tool-embed.html
│   ├── tools/
│   │   ├── list.html
│   │   └── single.html
│   └── writeups/single.html
├── static/
│   ├── ads.txt
│   ├── css/                            # Additional CSS
│   ├── games/
│   │   ├── deploy-on-friday/index.html
│   │   └── sudo-type/index.html
│   ├── images/                         # Logos, banners, icons (excluded from tree)
│   ├── js/
│   │   ├── iframe-resizer.js
│   │   └── tools/
│   │       ├── base64.js
│   │       ├── caesar.js
│   │       └── hash.js
│   ├── manifest.json                   # PWA manifest
│   ├── robots.txt
│   ├── sw.js                           # Service Worker
│   └── tools/
│       ├── easy-cron/index.html
│       ├── freelance-calculator/index.html
│       ├── glitch-forge/index.html
│       ├── netguard/index.html         # ← Source in Section 3a
│       ├── pass-fort/index.html
│       ├── pixel-shrink/index.html     # ← Source in Section 3b
│       ├── reflex-grid/index.html
│       └── zen-focus/index.html
├── ARCHITECTURE.md
├── CNAME                               # federicosella.com
├── hugo.toml                           # ← Full content in Section 2
├── LICENSE
├── README.md
└── themes/PaperMod/                    # Git submodule (excluded from tree)
```

---

## 2. Key Configuration — `hugo.toml`

```toml
baseURL = 'https://federicosella.com/'
languageCode = 'en-us'
title = 'Federico Sella'
theme = 'PaperMod'
defaultContentLanguage = 'en'
defaultContentLanguageInSubdir = true

# Fondamentale per evitare conflitti URL
[permalinks]
  posts = "/:year/:month/:title/"
  news = "/news/:year/:month/:title/"

# Taxonomies per categorizzazione contenuti
[taxonomies]
  category = "categories"
  tag = "tags"
  news-category = "news-categories"

# Sitemap configuration for SEO
[sitemap]
  changefreq = "weekly"
  priority = 0.5
  filename = "sitemap.xml"

# Google Analytics 4
[services]
  [services.googleAnalytics]
    ID = 'G-MDQF90PHTW'

[params]
  defaultTheme = "dark"
  env = "production"
  title = "Federico Sella"
  description = "Portfolio of Federico Sella - Security Developer, SOC Analyst & Red Team Enthusiast. Expert in Industrial Automation (CNC) bridging OT and IT Security."
  keywords = ["Federico Sella", "Cybersecurity Portfolio", "Red Team", "SOC Analyst", "Industrial Cybersecurity", "CNC Programmer", "Python Developer", "Bergamo"]
  author = "Federico Sella"
  images = ["images/logo.webp"]
  ShowShareButtons = true

  [params.assets]
    favicon = "/favicon.png"
    favicon16x16 = "/favicon.png"
    favicon32x32 = "/favicon.png"
    apple_touch_icon = "/favicon.png"

  [params.profileMode]
    enabled = true
    title = "Federico Sella"
    subtitle = "Security Developer | Red Teamer | Industrial Specialist"
    imageUrl = "images/logo.webp"
    imageTitle = "Federico Sella"
    buttons = [
      { name = "About Me", url = "about/" },
      { name = "My Projects", url = "projects/" },
      { name = "Contact", url = "mailto:fedesella95@gmail.com" }
    ]

    [[params.socialIcons]]
      name = "linkedin"
      url = "https://linkedin.com/in/federicosella"
    [[params.socialIcons]]
      name = "github"
      url = "https://github.com/fede952"
    [params.label]
    text = "Federico Sella"
    icon = "images/logo.webp"
    iconHeight = 35

  [[params.featured_tools]]
    name = "RateMate 💰"
    description = "Freelance Income & Tax Calculator"
    url = "tools/freelance-calculator/"
    color = "linear-gradient(135deg, #10b981 0%, #059669 100%)"

  [[params.featured_tools]]
    name = "ReflexGrid 🎯"
    description = "Pro Aim Trainer & Reaction Test"
    url = "tools/reflex-grid/"
    color = "linear-gradient(135deg, #ef4444 0%, #b91c1c 100%)"

  [[params.featured_tools]]
    name = "PassFort 🛡️"
    description = "Password Security Auditor"
    url = "tools/pass-fort/"
    color = "linear-gradient(135deg, #3b82f6 0%, #1d4ed8 100%)"

# --- Language Configuration (12 languages) ---

[languages]
  [languages.en]
    languageName = "English"
    weight = 1
    contentDir = "content"
    # Menu: About Me, Tech News, Guides, Tools, Games, CTF Writeups, Projects

  [languages.it]
    languageName = "Italiano"
    weight = 2

  [languages.es]
    languageName = "Español"
    weight = 3

  [languages.zh-cn]
    languageName = "简体中文"
    weight = 4

  [languages.hi]
    languageName = "हिन्दी"
    weight = 5

  [languages.ar]
    languageName = "العربية"
    weight = 6
    languagedirection = "rtl"

  [languages.pt]
    languageName = "Português"
    weight = 7

  [languages.fr]
    languageName = "Français"
    weight = 8

  [languages.de]
    languageName = "Deutsch"
    weight = 9

  [languages.ja]
    languageName = "日本語"
    weight = 10

  [languages.ru]
    languageName = "Русский"
    weight = 11

  [languages.ko]
    languageName = "한국어"
    weight = 12

# Each language has a full nav menu (About, News, Guides, Tools, Games, Writeups, Projects).
# Full menu definitions omitted for brevity — see hugo.toml for complete config.

[markup]
  [markup.goldmark]
    [markup.goldmark.renderer]
      unsafe = true
```

---

## 3a. Tool Source Code — `static/tools/netguard/index.html`

```html
<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>NetGuard - Browser Leak & Fingerprint Detector</title>
<style>
*,*::before,*::after{box-sizing:border-box;margin:0;padding:0}
:root{
  --bg:#0a0a0a;--bg2:#111;--bg3:#171717;--bg4:#1e1e1e;
  --green:#00ff41;--green-dim:#00cc33;--green-glow:rgba(0,255,65,.15);
  --red:#ff3333;--orange:#ff9900;--yellow:#ccff00;--cyan:#00e5ff;
  --text:#b0b0b0;--text2:#666;--text3:#444;
  --border:#222;--border2:#2a2a2a;
  --mono:'SF Mono','Cascadia Code','Fira Code',Consolas,'Courier New',monospace;
}
html,body{min-height:100%;background:var(--bg);color:var(--text);font-family:var(--mono);-webkit-font-smoothing:antialiased}

.app{max-width:780px;margin:0 auto;padding:16px;display:flex;flex-direction:column;gap:14px}

/* Header */
.header{text-align:center;padding:18px 0;border-bottom:2px solid var(--green)}
.header h1{font-size:clamp(20px,4.5vw,30px);color:var(--green);text-transform:uppercase;letter-spacing:5px;text-shadow:0 0 20px var(--green-glow)}
.header .sub{font-size:12px;color:var(--text2);margin-top:6px;letter-spacing:1.5px}

/* Scan Button */
.scan-btn{display:block;width:100%;padding:16px;font-family:var(--mono);font-size:15px;font-weight:700;text-transform:uppercase;letter-spacing:4px;background:transparent;color:var(--green);border:2px solid var(--green);border-radius:6px;cursor:pointer;transition:all .2s;text-align:center}
.scan-btn:hover{background:var(--green);color:var(--bg);box-shadow:0 0 30px var(--green-glow)}
.scan-btn:disabled{opacity:.5;cursor:not-allowed}
.scan-btn.scanning{animation:pulse-border 1s infinite}
@keyframes pulse-border{0%,100%{border-color:var(--green);box-shadow:0 0 10px var(--green-glow)}50%{border-color:var(--green-dim);box-shadow:0 0 30px var(--green-glow)}}

/* Status Bar */
.status{text-align:center;font-size:12px;color:var(--green);letter-spacing:1px;min-height:18px;opacity:.8}
.status .blink{animation:blink .6s step-end infinite}
@keyframes blink{50%{opacity:0}}

/* Grid */
.grid{display:grid;grid-template-columns:1fr 1fr;gap:12px}
.card{background:var(--bg2);border:1px solid var(--border);border-radius:8px;padding:16px;transition:border-color .3s}
.card.revealed{border-color:var(--green);box-shadow:0 0 8px rgba(0,255,65,.06)}
.card.warn{border-color:var(--red);box-shadow:0 0 8px rgba(255,51,51,.1)}
.card.full{grid-column:1 / -1}
.card-label{font-size:10px;text-transform:uppercase;letter-spacing:2px;color:var(--text3);margin-bottom:8px}
.card-value{font-size:clamp(14px,3vw,20px);color:var(--green);word-break:break-all;line-height:1.4;min-height:24px}
.card-value.warn{color:var(--red)}
.card-value.safe{color:var(--green)}
.card-value.pending{color:var(--text3);font-style:italic;font-size:13px}
.card-sub{font-size:11px;color:var(--text2);margin-top:4px}

/* Section */
.section-title{font-size:11px;text-transform:uppercase;letter-spacing:3px;color:var(--cyan);padding:10px 0;border-bottom:1px solid var(--border);margin-bottom:2px;grid-column:1 / -1}

/* Privacy Score */
.score-wrap{text-align:center;padding:20px;background:var(--bg2);border:1px solid var(--border);border-radius:8px}
.score-ring{position:relative;width:120px;height:120px;margin:0 auto 12px}
.score-ring svg{width:120px;height:120px;transform:rotate(-90deg)}
.score-ring circle{fill:none;stroke-width:8;stroke-linecap:round}
.score-ring .bg-ring{stroke:var(--border2)}
.score-ring .fg-ring{stroke:var(--green);stroke-dasharray:339.292;stroke-dashoffset:339.292;transition:stroke-dashoffset 1.5s ease,stroke 1s ease}
.score-num{position:absolute;inset:0;display:flex;align-items:center;justify-content:center;font-size:32px;font-weight:700;color:var(--green)}
.score-label{font-size:12px;color:var(--text2);text-transform:uppercase;letter-spacing:2px}

/* Ad Placeholder */
.ad-unit{min-height:100px;background:#0d0d0d;border:1px dashed var(--border2);border-radius:6px;display:flex;align-items:center;justify-content:center;color:var(--text3);font-size:11px;text-transform:uppercase;letter-spacing:2px}

/* WebRTC table */
.leak-list{list-style:none;padding:0}
.leak-list li{display:flex;align-items:center;gap:8px;padding:6px 0;font-size:13px;border-bottom:1px solid var(--border)}
.leak-list li:last-child{border-bottom:none}
.leak-dot{width:8px;height:8px;border-radius:50%;flex-shrink:0}
.leak-dot.red{background:var(--red)}
.leak-dot.green{background:var(--green)}

/* Responsive */
@media(max-width:640px){
  .grid{grid-template-columns:1fr}
  .card.full{grid-column:1}
  .section-title{grid-column:1}
  .app{padding:10px;gap:10px}
}
</style>
</head>
<body>
<div class="app">

  <header class="header">
    <h1>Net<span style="color:#fff">Guard</span></h1>
    <div class="sub">Browser Leak &amp; Fingerprint Detector</div>
  </header>

  <div id="vpn-cta" style="margin: 20px auto; text-align: center; max-width: 800px;">
    <a href="https://go.nordvpn.net/aff_c?offer_id=15&aff_id=140342&url_id=858" target="_blank" rel="noopener noreferrer nofollow" style="display: block;">
      <picture>
        <source media="(max-width: 767px)" srcset="/images/nordvpn-box.png">
        <source media="(min-width: 768px)" srcset="/images/nordvpn-wide.png">
        <img src="/images/nordvpn-wide.png" alt="NordVPN Secure Deal" style="width: 100%; height: auto; border-radius: 4px; box-shadow: 0 4px 12px rgba(0,0,0,0.3);">
      </picture>
    </a>
    <p style="font-size: 10px; color: #555; margin-top: 5px; text-transform: uppercase; letter-spacing: 1px;">Sponsored</p>
  </div>

  <button class="scan-btn" id="scanBtn">Run Privacy Scan</button>
  <div class="status" id="status"></div>

  <!-- Privacy Score -->
  <div class="score-wrap" id="scoreWrap" style="display:none">
    <div class="score-ring">
      <svg viewBox="0 0 120 120"><circle class="bg-ring" cx="60" cy="60" r="54"/><circle class="fg-ring" id="scoreArc" cx="60" cy="60" r="54"/></svg>
      <div class="score-num" id="scoreNum">-</div>
    </div>
    <div class="score-label">Privacy Score</div>
  </div>

  <div class="grid" id="results">

    <div class="section-title">Network &amp; Location</div>

    <div class="card" id="cardIp">
      <div class="card-label">Public IP Address</div>
      <div class="card-value pending" id="valIp">Waiting for scan...</div>
    </div>
    <div class="card" id="cardIsp">
      <div class="card-label">ISP / Organization</div>
      <div class="card-value pending" id="valIsp">Waiting for scan...</div>
    </div>

    <div class="card full" id="vpn-cta" style="display:none;text-align:center;background:transparent;border:none;padding:0;box-shadow:none">
      <a href="https://go.nordvpn.net/aff_c?offer_id=15&aff_id=140342&url_id=858" target="_blank" rel="noopener noreferrer nofollow">
        <picture>
          <source media="(min-width:768px)" srcset="/images/nordvpn-wide.png">
          <img src="/images/nordvpn-box.png" alt="Get NordVPN - Protect Your Privacy" style="max-width:100%;height:auto;display:block;margin:0 auto;border-radius:8px;box-shadow:0 4px 20px rgba(0,0,0,.5)">
        </picture>
      </a>
    </div>
    <div class="card" id="cardLoc">
      <div class="card-label">Location</div>
      <div class="card-value pending" id="valLoc">Waiting for scan...</div>
    </div>
    <div class="card" id="cardSpeed">
      <div class="card-label">Connection Speed</div>
      <div class="card-value pending" id="valSpeed">Waiting for scan...</div>
    </div>

    <div class="section-title">Browser Fingerprint</div>

    <div class="card" id="cardOs">
      <div class="card-label">Operating System</div>
      <div class="card-value pending" id="valOs">Waiting for scan...</div>
    </div>
    <div class="card" id="cardBrowser">
      <div class="card-label">Browser</div>
      <div class="card-value pending" id="valBrowser">Waiting for scan...</div>
    </div>
    <div class="card" id="cardScreen">
      <div class="card-label">Screen Resolution</div>
      <div class="card-value pending" id="valScreen">Waiting for scan...</div>
    </div>
    <div class="card" id="cardGpu">
      <div class="card-label">GPU Renderer</div>
      <div class="card-value pending" id="valGpu">Waiting for scan...</div>
    </div>
    <div class="card" id="cardBattery">
      <div class="card-label">Battery Level</div>
      <div class="card-value pending" id="valBattery">Waiting for scan...</div>
    </div>
    <div class="card" id="cardLang">
      <div class="card-label">Language / Timezone</div>
      <div class="card-value pending" id="valLang">Waiting for scan...</div>
    </div>

    <div class="section-title">WebRTC Leak Test</div>

    <div class="card full" id="cardWebrtc">
      <div class="card-label">WebRTC Local IP Exposure</div>
      <div class="card-value pending" id="valWebrtc">Waiting for scan...</div>
      <ul class="leak-list" id="leakList" style="display:none"></ul>
    </div>

  </div>

  <div class="ad-unit">Advertisement</div>

</div>

<script>
/* ── Utilities ── */
function $(id){return document.getElementById(id)}
function setCard(id,value,cls){
  const el=$(id);
  el.textContent=value;
  el.className='card-value'+(cls?' '+cls:'');
  const card=el.closest('.card');
  if(card){card.classList.add(cls==='warn'?'warn':'revealed')}
}
function setStatus(msg){$('status').innerHTML=msg}

let privacyDeductions=0;

/* ── IP & Location (ipwho.is — HTTPS) ── */
async function scanNetwork(){
  setStatus('Scanning network identity<span class="blink">...</span>');
  try{
    const r=await fetch('https://ipwho.is/');
    const d=await r.json();
    setCard('valIp',d.ip,'warn');
    $('vpn-cta').style.display='block';
    setCard('valIsp',(d.connection&&d.connection.isp)||d.org||'Unknown');
    setCard('valLoc',(d.city?d.city+', ':'')+d.country);
    $('cardLoc').querySelector('.card-sub')?.remove();
    if(d.latitude&&d.longitude){
      const sub=document.createElement('div');
      sub.className='card-sub';
      sub.textContent='Lat '+d.latitude.toFixed(2)+', Lon '+d.longitude.toFixed(2);
      $('cardLoc').appendChild(sub);
    }
    privacyDeductions+=30;
  }catch(e){
    setCard('valIp','Could not detect','safe');
    setCard('valIsp','Hidden');
    setCard('valLoc','Hidden');
  }
}

/* ── Connection Speed ── */
function scanSpeed(){
  const c=navigator.connection||navigator.mozConnection||navigator.webkitConnection;
  if(c&&c.downlink){
    setCard('valSpeed',c.downlink+' Mbps ('+c.effectiveType+')');
    const sub=document.createElement('div');
    sub.className='card-sub';
    sub.textContent='RTT ~'+c.rtt+'ms';
    $('cardSpeed').appendChild(sub);
  }else{
    setCard('valSpeed','API not available','pending');
  }
}

/* ── Browser Fingerprint ── */
function scanFingerprint(){
  setStatus('Scanning browser fingerprint<span class="blink">...</span>');
  /* OS */
  const ua=navigator.userAgent;
  let os='Unknown';
  if(ua.includes('Windows NT 10'))os='Windows 10/11';
  else if(ua.includes('Windows'))os='Windows';
  else if(ua.includes('Mac OS X'))os='macOS';
  else if(ua.includes('Android'))os='Android';
  else if(ua.includes('iPhone')||ua.includes('iPad'))os='iOS';
  else if(ua.includes('Linux'))os='Linux';
  else if(ua.includes('CrOS'))os='Chrome OS';
  setCard('valOs',os);
  const pf=navigator.platform||'';
  if(pf){
    const sub=document.createElement('div');
    sub.className='card-sub';
    sub.textContent='Platform: '+pf;
    $('cardOs').appendChild(sub);
  }

  /* Browser */
  let browser='Unknown';
  if(ua.includes('Firefox/'))browser='Firefox '+ua.split('Firefox/')[1].split(' ')[0];
  else if(ua.includes('Edg/'))browser='Edge '+ua.split('Edg/')[1].split(' ')[0];
  else if(ua.includes('OPR/')||ua.includes('Opera'))browser='Opera';
  else if(ua.includes('Chrome/'))browser='Chrome '+ua.split('Chrome/')[1].split(' ')[0];
  else if(ua.includes('Safari/'))browser='Safari';
  setCard('valBrowser',browser);

  /* Screen */
  setCard('valScreen',screen.width+'x'+screen.height+' @ '+window.devicePixelRatio+'x');
  const sub2=document.createElement('div');
  sub2.className='card-sub';
  sub2.textContent='Viewport: '+window.innerWidth+'x'+window.innerHeight+', Depth: '+screen.colorDepth+'bit';
  $('cardScreen').appendChild(sub2);
  privacyDeductions+=10;

  /* GPU */
  try{
    const c=document.createElement('canvas');
    const gl=c.getContext('webgl')||c.getContext('experimental-webgl');
    if(gl){
      const dbg=gl.getExtension('WEBGL_debug_renderer_info');
      if(dbg){
        const renderer=gl.getParameter(dbg.UNMASKED_RENDERER_WEBGL);
        const vendor=gl.getParameter(dbg.UNMASKED_VENDOR_WEBGL);
        setCard('valGpu',renderer,'warn');
        const sub3=document.createElement('div');
        sub3.className='card-sub';
        sub3.textContent='Vendor: '+vendor;
        $('cardGpu').appendChild(sub3);
        privacyDeductions+=10;
      }else{
        setCard('valGpu','Debug info blocked','safe');
      }
    }else{
      setCard('valGpu','WebGL not available','safe');
    }
  }catch(e){
    setCard('valGpu','Blocked','safe');
  }

  /* Language / Timezone */
  const lang=navigator.language||navigator.userLanguage||'Unknown';
  let tz;
  try{tz=Intl.DateTimeFormat().resolvedOptions().timeZone}catch(e){tz='Unknown'}
  setCard('valLang',lang+' / '+tz);
  privacyDeductions+=5;
}

/* ── Battery ── */
async function scanBattery(){
  try{
    if(navigator.getBattery){
      const b=await navigator.getBattery();
      const pct=Math.round(b.level*100);
      const charging=b.charging?' (Charging)':' (Discharging)';
      setCard('valBattery',pct+'%'+charging,'warn');
      privacyDeductions+=5;
    }else{
      setCard('valBattery','API not available','safe');
    }
  }catch(e){
    setCard('valBattery','Blocked by browser','safe');
  }
}

/* ── WebRTC Leak ── */
function scanWebRTC(){
  return new Promise(resolve=>{
    setStatus('Testing WebRTC leaks<span class="blink">...</span>');
    const ips=new Set();
    try{
      const pc=new RTCPeerConnection({iceServers:[]});
      pc.createDataChannel('');
      pc.createOffer().then(o=>pc.setLocalDescription(o)).catch(()=>{});
      pc.onicecandidate=e=>{
        if(!e||!e.candidate){
          pc.close();
          showWebRTCResults(ips);
          resolve();
          return;
        }
        const parts=e.candidate.candidate.split(' ');
        const ip=parts[4];
        if(ip&&!ip.includes(':')){
          /* skip mDNS */
          if(!ip.endsWith('.local'))ips.add(ip);
        }
      };
      setTimeout(()=>{try{pc.close()}catch(e){}showWebRTCResults(ips);resolve()},4000);
    }catch(e){
      setCard('valWebrtc','WebRTC unavailable','safe');
      resolve();
    }
  });
}

function showWebRTCResults(ips){
  const list=$('leakList');
  if(ips.size===0){
    setCard('valWebrtc','No local IPs leaked','safe');
    $('cardWebrtc').classList.add('revealed');
    list.style.display='block';
    list.innerHTML='<li><span class="leak-dot green"></span> WebRTC is not exposing private IPs</li>';
  }else{
    setCard('valWebrtc',ips.size+' IP(s) leaked via WebRTC','warn');
    $('cardWebrtc').classList.add('warn');
    list.style.display='block';
    list.innerHTML='';
    ips.forEach(ip=>{
      list.innerHTML+='<li><span class="leak-dot red"></span> '+ip+' <span style="color:var(--text3);font-size:11px">(exposed)</span></li>';
    });
    privacyDeductions+=20;
  }
}

/* ── Privacy Score ── */
function showScore(){
  const score=Math.max(0,100-privacyDeductions);
  $('scoreWrap').style.display='block';
  $('scoreNum').textContent=score;
  const arc=$('scoreArc');
  const circumference=2*Math.PI*54;
  const offset=circumference-((score/100)*circumference);
  arc.style.strokeDashoffset=offset;
  if(score>=70){
    arc.style.stroke='var(--green)';
    $('scoreNum').style.color='var(--green)';
  }else if(score>=40){
    arc.style.stroke='var(--orange)';
    $('scoreNum').style.color='var(--orange)';
  }else{
    arc.style.stroke='var(--red)';
    $('scoreNum').style.color='var(--red)';
  }
}

/* ── Main Scan ── */
async function runScan(){
  const btn=$('scanBtn');
  btn.disabled=true;
  btn.classList.add('scanning');
  btn.textContent='Scanning...';
  privacyDeductions=0;

  /* Reset cards */
  document.querySelectorAll('.card').forEach(c=>{c.classList.remove('revealed','warn')});

  await scanNetwork();
  scanSpeed();
  scanFingerprint();
  await scanBattery();
  await scanWebRTC();

  showScore();
  setStatus('Scan complete. Your browser is exposing the data above.');
  btn.disabled=false;
  btn.classList.remove('scanning');
  btn.textContent='Scan Again';
}

$('scanBtn').addEventListener('click',runScan);
</script>
<script>
/* AUTO-RESIZE SENDER */
(function(){
  function sendHeight(){
    var h=document.body.scrollHeight;
    window.parent.postMessage({type:"setHeight",height:h},"*");
  }
  document.documentElement.style.height="auto";
  document.body.style.height="auto";
  document.body.style.minHeight="0";
  window.addEventListener("load",sendHeight);
  window.addEventListener("resize",sendHeight);
  new MutationObserver(sendHeight).observe(document.body,{subtree:true,childList:true});
})();
</script>
</body>
</html>
```

---

## 3b. Tool Source Code — `static/tools/pixel-shrink/index.html`

```html
<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>PixelShrink Pro - Privacy-First Image Compressor</title>
<script src="https://cdn.jsdelivr.net/npm/browser-image-compression@2.0.2/dist/browser-image-compression.js"></script>
<style>
*,*::before,*::after{box-sizing:border-box;margin:0;padding:0}
:root{
  --bg:#08080c;--bg2:#0e0e14;--bg3:#14141e;--bg4:#1a1a28;
  --cyan:#00e5ff;--cyan-dim:#00b8d4;--cyan-glow:rgba(0,229,255,.12);
  --magenta:#ff2dce;--magenta-glow:rgba(255,45,206,.1);
  --green:#00ff88;--red:#ff3355;--orange:#ff9900;
  --text:#c0c0cc;--text2:#666680;--text3:#3a3a50;
  --border:#1e1e30;--border2:#2a2a40;
  --mono:'SF Mono','Cascadia Code','Fira Code',Consolas,'Courier New',monospace;
}
html,body{min-height:100%;background:var(--bg);color:var(--text);font-family:var(--mono);-webkit-font-smoothing:antialiased}

.app{max-width:720px;margin:0 auto;padding:20px;display:flex;flex-direction:column;gap:16px}

/* Header */
.header{text-align:center;padding:24px 0;border-bottom:2px solid var(--cyan);position:relative}
.header::after{content:'';position:absolute;bottom:-2px;left:0;width:100%;height:2px;background:linear-gradient(90deg,transparent,var(--cyan),var(--magenta),transparent)}
.header img{width:80px;margin-bottom:12px;filter:drop-shadow(0 0 12px var(--cyan-glow))}
.header h1{font-size:clamp(22px,5vw,32px);text-transform:uppercase;letter-spacing:6px;background:linear-gradient(135deg,var(--cyan),var(--magenta));-webkit-background-clip:text;-webkit-text-fill-color:transparent;background-clip:text}
.header .sub{font-size:11px;color:var(--text2);margin-top:8px;letter-spacing:2px}

/* Drop Zone */
.dropzone{position:relative;border:2px dashed var(--border2);border-radius:12px;padding:52px 24px;text-align:center;cursor:pointer;transition:all .3s ease;background:var(--bg2);min-height:200px;display:flex;flex-direction:column;align-items:center;justify-content:center;gap:10px}
.dropzone:hover{border-color:var(--cyan);background:var(--cyan-glow);box-shadow:0 0 40px rgba(0,229,255,.05)}
.dropzone.dragover{border-color:var(--magenta);background:var(--magenta-glow);box-shadow:0 0 60px rgba(255,45,206,.08);transform:scale(1.01)}
.dropzone .dz-icon{font-size:44px;line-height:1;transition:transform .3s}
.dropzone.dragover .dz-icon{transform:scale(1.2)}
.dropzone .dz-label{font-size:14px;color:var(--text);letter-spacing:1px}
.dropzone .dz-hint{font-size:11px;color:var(--text3)}
.dropzone input[type=file]{position:absolute;inset:0;opacity:0;cursor:pointer}
.dropzone.processing{animation:pulse-cyan 1.2s ease infinite}
@keyframes pulse-cyan{0%,100%{border-color:var(--cyan);box-shadow:0 0 12px var(--cyan-glow)}50%{border-color:var(--magenta);box-shadow:0 0 30px var(--magenta-glow)}}

/* Preview */
.preview{display:none;text-align:center}
.preview img{max-width:100%;max-height:240px;border-radius:8px;border:1px solid var(--border2);display:block;margin:0 auto 8px}
.preview-name{font-size:11px;color:var(--text2);word-break:break-all}
.preview-dim{font-size:11px;color:var(--text3);margin-top:2px}

/* Controls Grid */
.controls{display:grid;grid-template-columns:1fr 1fr;gap:12px}
.ctrl{background:var(--bg2);border:1px solid var(--border);border-radius:8px;padding:14px}
.ctrl-label{font-size:10px;text-transform:uppercase;letter-spacing:2px;color:var(--text3);margin-bottom:8px;display:block}
.ctrl select,.ctrl input[type=number]{width:100%;padding:10px;font-family:var(--mono);font-size:13px;background:var(--bg4);color:var(--text);border:1px solid var(--border);border-radius:6px;outline:none;transition:border-color .2s}
.ctrl select:focus,.ctrl input[type=number]:focus{border-color:var(--cyan)}
.ctrl input[type=number]{-moz-appearance:textfield}
.ctrl input[type=number]::-webkit-inner-spin-button{opacity:1}

/* Slider */
.slider-row{display:flex;align-items:center;gap:10px}
.slider-row input[type=range]{flex:1;-webkit-appearance:none;height:6px;border-radius:3px;background:var(--bg4);outline:none}
.slider-row input[type=range]::-webkit-slider-thumb{-webkit-appearance:none;width:18px;height:18px;border-radius:50%;background:var(--cyan);cursor:pointer;box-shadow:0 0 10px var(--cyan-glow)}
.slider-row input[type=range]::-moz-range-thumb{width:18px;height:18px;border-radius:50%;background:var(--cyan);cursor:pointer;border:none}
.slider-val{font-size:18px;color:var(--cyan);font-weight:700;min-width:36px;text-align:right}

/* Compress Button */
.compress-btn{display:block;width:100%;padding:16px;font-family:var(--mono);font-size:15px;font-weight:700;text-transform:uppercase;letter-spacing:4px;background:transparent;color:var(--cyan);border:2px solid var(--cyan);border-radius:8px;cursor:pointer;transition:all .25s;text-align:center}
.compress-btn:hover{background:var(--cyan);color:var(--bg);box-shadow:0 0 40px var(--cyan-glow)}
.compress-btn:disabled{opacity:.35;cursor:not-allowed}
.compress-btn:disabled:hover{background:transparent;color:var(--cyan);box-shadow:none}

/* Status */
.status{text-align:center;font-size:12px;color:var(--cyan);letter-spacing:1px;min-height:18px;opacity:.85}
.status .blink{animation:blink .6s step-end infinite}
@keyframes blink{50%{opacity:0}}

/* Results */
.results{display:none;background:var(--bg2);border:1px solid var(--border);border-radius:10px;padding:22px;position:relative;overflow:hidden}
.results::before{content:'';position:absolute;top:0;left:0;width:100%;height:2px;background:linear-gradient(90deg,var(--cyan),var(--magenta))}
.results.visible{display:block}
.stats-grid{display:grid;grid-template-columns:1fr auto 1fr;gap:16px;align-items:center}
.stat-col{text-align:center}
.stat-heading{font-size:10px;text-transform:uppercase;letter-spacing:2px;color:var(--text3);margin-bottom:8px}
.stat-size{font-size:clamp(18px,3.5vw,24px);font-weight:700;color:var(--text)}
.stat-dim{font-size:11px;color:var(--text3);margin-top:4px}
.stat-col.after .stat-size{color:var(--cyan)}
.stat-arrow{font-size:24px;color:var(--magenta);opacity:.7}
.saved-row{text-align:center;margin-top:16px;padding-top:14px;border-top:1px solid var(--border)}
.saved-pct{font-size:clamp(22px,4vw,30px);font-weight:700;background:linear-gradient(135deg,var(--cyan),var(--green));-webkit-background-clip:text;-webkit-text-fill-color:transparent;background-clip:text}
.saved-label{font-size:10px;text-transform:uppercase;letter-spacing:2px;color:var(--text3);margin-top:4px}

/* Download */
.download-btn{display:none;width:100%;padding:16px;font-family:var(--mono);font-size:14px;font-weight:700;text-transform:uppercase;letter-spacing:3px;background:linear-gradient(135deg,var(--cyan),var(--magenta));color:#fff;border:none;border-radius:8px;cursor:pointer;transition:all .25s;text-align:center;text-decoration:none}
.download-btn:hover{box-shadow:0 0 40px var(--cyan-glow),0 0 40px var(--magenta-glow);opacity:.92}
.download-btn.visible{display:block}

/* Responsive */
@media(max-width:600px){
  .controls{grid-template-columns:1fr}
  .stats-grid{grid-template-columns:1fr;gap:8px}
  .stat-arrow{transform:rotate(90deg);margin:0 auto}
  .app{padding:12px;gap:12px}
}
</style>
</head>
<body>
<div class="app">

  <header class="header">
    <img src="/images/pixel-shrink-icon.png" alt="PixelShrink">
    <h1>PixelShrink <span style="font-size:.5em;opacity:.6">PRO</span></h1>
    <div class="sub" id="subtitle"></div>
  </header>

  <div class="dropzone" id="dropzone">
    <div class="dz-icon">&#128444;&#65039;</div>
    <div class="dz-label" id="dropLabel"></div>
    <div class="dz-hint" id="dropHint"></div>
    <input type="file" id="fileInput" accept="image/png,image/jpeg,image/webp,image/avif">
  </div>

  <div class="preview" id="preview">
    <img id="previewImg" alt="Preview">
    <div class="preview-name" id="previewName"></div>
    <div class="preview-dim" id="previewDim"></div>
  </div>

  <div class="controls">
    <div class="ctrl">
      <span class="ctrl-label" id="formatLabel"></span>
      <select id="formatSelect"></select>
    </div>
    <div class="ctrl">
      <span class="ctrl-label" id="qualityLabel"></span>
      <div class="slider-row">
        <input type="range" id="qualitySlider" min="1" max="100" value="75">
        <span class="slider-val" id="qualityVal">75</span>
      </div>
    </div>
    <div class="ctrl">
      <span class="ctrl-label" id="maxSizeLabel"></span>
      <input type="number" id="maxSizeInput" min="0.01" max="100" step="0.1" value="10" placeholder="10">
    </div>
    <div class="ctrl">
      <span class="ctrl-label" id="maxWidthLabel"></span>
      <input type="number" id="maxWidthInput" min="1" max="16384" step="1" value="4096" placeholder="4096">
    </div>
  </div>

  <button class="compress-btn" id="compressBtn" disabled></button>
  <div class="status" id="status"></div>

  <div class="results" id="results">
    <div class="stats-grid">
      <div class="stat-col before">
        <div class="stat-heading" id="beforeLabel"></div>
        <div class="stat-size" id="beforeSize">-</div>
        <div class="stat-dim" id="beforeDim"></div>
      </div>
      <div class="stat-arrow">&#10132;</div>
      <div class="stat-col after">
        <div class="stat-heading" id="afterLabel"></div>
        <div class="stat-size" id="afterSize">-</div>
        <div class="stat-dim" id="afterDim"></div>
      </div>
    </div>
    <div class="saved-row">
      <div class="saved-pct" id="savedPct">-</div>
      <div class="saved-label" id="savedLabel"></div>
    </div>
  </div>

  <a class="download-btn" id="downloadBtn" download></a>

</div>

<script>
/* LANGUAGE DETECTION — Priority: URL param > parent iframe path > navigator.language > 'en' */
var SUPPORTED_LANGS = ['en','it','es','fr','de','pt','ru','ja','zh'];

function detectLang() {
  var params = new URLSearchParams(window.location.search);
  var p = (params.get('lang') || '').toLowerCase().split('-')[0];
  if (p && SUPPORTED_LANGS.indexOf(p) !== -1) return p;
  try {
    var parentPath = window.parent.location.pathname || '';
    var segs = parentPath.split('/').filter(Boolean);
    if (segs.length > 0) {
      var first = segs[0].toLowerCase().split('-')[0];
      if (SUPPORTED_LANGS.indexOf(first) !== -1) return first;
    }
  } catch (e) {}
  var nav = (navigator.language || '').toLowerCase().split('-')[0];
  if (nav && SUPPORTED_LANGS.indexOf(nav) !== -1) return nav;
  return 'en';
}

/* DICTIONARY (9 languages) */
var DICT = {
  en: { subtitle:"Privacy-First Image Compressor", dropLabel:"Drag & Drop your image here",
    dropHint:"PNG \u2022 JPG \u2022 WebP \u2022 AVIF \u2014 processed locally",
    formatLabel:"Output Format", optKeep:"Keep Original", qualityLabel:"Quality",
    maxSizeLabel:"Max Size (MB)", maxWidthLabel:"Max Width (px)",
    compressBtn:"Compress Image", processing:"Processing",
    beforeLabel:"Before", afterLabel:"After", savedLabel:"Space Saved",
    downloadBtn:"Download Compressed Image",
    done:"Done! Your image never left your browser.",
    noFile:"Drop an image first.", avifNotSupported:"AVIF not supported by this browser" },
  it: { subtitle:"Compressore Immagini Privacy-First", dropLabel:"Trascina la tua immagine qui",
    dropHint:"PNG \u2022 JPG \u2022 WebP \u2022 AVIF \u2014 elaborazione locale",
    formatLabel:"Formato Output", optKeep:"Mantieni Originale", qualityLabel:"Qualit\u00e0",
    maxSizeLabel:"Dim. Max (MB)", maxWidthLabel:"Largh. Max (px)",
    compressBtn:"Comprimi Immagine", processing:"Elaborazione",
    beforeLabel:"Prima", afterLabel:"Dopo", savedLabel:"Spazio Risparmiato",
    downloadBtn:"Scarica Immagine Compressa",
    done:"Fatto! La tua immagine non ha mai lasciato il browser.",
    noFile:"Trascina prima un\u2019immagine.", avifNotSupported:"AVIF non supportato da questo browser" },
  es: { subtitle:"Compresor de Im\u00e1genes Privado", dropLabel:"Arrastra tu imagen aqu\u00ed",
    dropHint:"PNG \u2022 JPG \u2022 WebP \u2022 AVIF \u2014 procesado localmente",
    formatLabel:"Formato de Salida", optKeep:"Mantener Original", qualityLabel:"Calidad",
    maxSizeLabel:"Tama\u00f1o M\u00e1x (MB)", maxWidthLabel:"Ancho M\u00e1x (px)",
    compressBtn:"Comprimir Imagen", processing:"Procesando",
    beforeLabel:"Antes", afterLabel:"Despu\u00e9s", savedLabel:"Espacio Ahorrado",
    downloadBtn:"Descargar Imagen Comprimida",
    done:"\u00a1Listo! Tu imagen nunca sali\u00f3 del navegador.",
    noFile:"Arrastra una imagen primero.", avifNotSupported:"AVIF no soportado por este navegador" },
  fr: { subtitle:"Compresseur d\u2019Images Priv\u00e9", dropLabel:"Glissez votre image ici",
    dropHint:"PNG \u2022 JPG \u2022 WebP \u2022 AVIF \u2014 traitement local",
    formatLabel:"Format de Sortie", optKeep:"Garder l\u2019Original", qualityLabel:"Qualit\u00e9",
    maxSizeLabel:"Taille Max (Mo)", maxWidthLabel:"Largeur Max (px)",
    compressBtn:"Compresser l\u2019Image", processing:"Traitement",
    beforeLabel:"Avant", afterLabel:"Apr\u00e8s", savedLabel:"Espace \u00c9conomis\u00e9",
    downloadBtn:"T\u00e9l\u00e9charger l\u2019Image Compress\u00e9e",
    done:"Termin\u00e9\u00a0! Votre image n\u2019a jamais quitt\u00e9 votre navigateur.",
    noFile:"Glissez d\u2019abord une image.", avifNotSupported:"AVIF non support\u00e9 par ce navigateur" },
  de: { subtitle:"Datenschutzfreundlicher Bildkompressor", dropLabel:"Bild hierher ziehen",
    dropHint:"PNG \u2022 JPG \u2022 WebP \u2022 AVIF \u2014 lokale Verarbeitung",
    formatLabel:"Ausgabeformat", optKeep:"Original beibehalten", qualityLabel:"Qualit\u00e4t",
    maxSizeLabel:"Max Gr\u00f6\u00dfe (MB)", maxWidthLabel:"Max Breite (px)",
    compressBtn:"Bild komprimieren", processing:"Verarbeitung",
    beforeLabel:"Vorher", afterLabel:"Nachher", savedLabel:"Platz Gespart",
    downloadBtn:"Komprimiertes Bild herunterladen",
    done:"Fertig! Dein Bild hat nie deinen Browser verlassen.",
    noFile:"Ziehe zuerst ein Bild hinein.", avifNotSupported:"AVIF wird von diesem Browser nicht unterst\u00fctzt" },
  pt: { subtitle:"Compressor de Imagens Privado", dropLabel:"Arraste sua imagem aqui",
    dropHint:"PNG \u2022 JPG \u2022 WebP \u2022 AVIF \u2014 processamento local",
    formatLabel:"Formato de Sa\u00edda", optKeep:"Manter Original", qualityLabel:"Qualidade",
    maxSizeLabel:"Tam. M\u00e1x (MB)", maxWidthLabel:"Larg. M\u00e1x (px)",
    compressBtn:"Comprimir Imagem", processing:"Processando",
    beforeLabel:"Antes", afterLabel:"Depois", savedLabel:"Espa\u00e7o Economizado",
    downloadBtn:"Baixar Imagem Comprimida",
    done:"Pronto! Sua imagem nunca saiu do navegador.",
    noFile:"Arraste uma imagem primeiro.", avifNotSupported:"AVIF n\u00e3o suportado por este navegador" },
  ru: { subtitle:"\u041a\u043e\u043c\u043f\u0440\u0435\u0441\u0441\u043e\u0440 \u0438\u0437\u043e\u0431\u0440\u0430\u0436\u0435\u043d\u0438\u0439",
    dropLabel:"\u041f\u0435\u0440\u0435\u0442\u0430\u0449\u0438\u0442\u0435 \u0438\u0437\u043e\u0431\u0440\u0430\u0436\u0435\u043d\u0438\u0435 \u0441\u044e\u0434\u0430",
    dropHint:"PNG \u2022 JPG \u2022 WebP \u2022 AVIF", formatLabel:"\u0424\u043e\u0440\u043c\u0430\u0442",
    optKeep:"\u0421\u043e\u0445\u0440\u0430\u043d\u0438\u0442\u044c \u043e\u0440\u0438\u0433\u0438\u043d\u0430\u043b",
    qualityLabel:"\u041a\u0430\u0447\u0435\u0441\u0442\u0432\u043e",
    maxSizeLabel:"\u041c\u0430\u043a\u0441. \u0440\u0430\u0437\u043c\u0435\u0440 (MB)",
    maxWidthLabel:"\u041c\u0430\u043a\u0441. \u0448\u0438\u0440\u0438\u043d\u0430 (px)",
    compressBtn:"\u0421\u0436\u0430\u0442\u044c", processing:"\u041e\u0431\u0440\u0430\u0431\u043e\u0442\u043a\u0430",
    beforeLabel:"\u0414\u043e", afterLabel:"\u041f\u043e\u0441\u043b\u0435",
    savedLabel:"\u042d\u043a\u043e\u043d\u043e\u043c\u0438\u044f",
    downloadBtn:"\u0421\u043a\u0430\u0447\u0430\u0442\u044c",
    done:"\u0413\u043e\u0442\u043e\u0432\u043e!", noFile:"\u041f\u0435\u0440\u0435\u0442\u0430\u0449\u0438\u0442\u0435 \u0438\u0437\u043e\u0431\u0440\u0430\u0436\u0435\u043d\u0438\u0435.",
    avifNotSupported:"AVIF \u043d\u0435 \u043f\u043e\u0434\u0434\u0435\u0440\u0436\u0438\u0432\u0430\u0435\u0442\u0441\u044f" },
  ja: { subtitle:"\u753b\u50cf\u5727\u7e2e\u30c4\u30fc\u30eb", dropLabel:"\u753b\u50cf\u3092\u30c9\u30e9\u30c3\u30b0\uff06\u30c9\u30ed\u30c3\u30d7",
    dropHint:"PNG \u2022 JPG \u2022 WebP \u2022 AVIF", formatLabel:"\u51fa\u529b\u5f62\u5f0f",
    optKeep:"\u5143\u306e\u5f62\u5f0f", qualityLabel:"\u54c1\u8cea",
    maxSizeLabel:"\u6700\u5927\u30b5\u30a4\u30ba (MB)", maxWidthLabel:"\u6700\u5927\u5e45 (px)",
    compressBtn:"\u5727\u7e2e", processing:"\u51e6\u7406\u4e2d",
    beforeLabel:"\u5727\u7e2e\u524d", afterLabel:"\u5727\u7e2e\u5f8c",
    savedLabel:"\u7bc0\u7d04\u91cf", downloadBtn:"\u30c0\u30a6\u30f3\u30ed\u30fc\u30c9",
    done:"\u5b8c\u4e86\uff01", noFile:"\u753b\u50cf\u3092\u30c9\u30ed\u30c3\u30d7\u3057\u3066\u304f\u3060\u3055\u3044\u3002",
    avifNotSupported:"AVIF\u975e\u5bfe\u5fdc" },
  zh: { subtitle:"\u56fe\u7247\u538b\u7f29\u5de5\u5177", dropLabel:"\u62d6\u653e\u56fe\u7247\u5230\u6b64\u5904",
    dropHint:"PNG \u2022 JPG \u2022 WebP \u2022 AVIF", formatLabel:"\u8f93\u51fa\u683c\u5f0f",
    optKeep:"\u4fdd\u6301\u539f\u59cb", qualityLabel:"\u8d28\u91cf",
    maxSizeLabel:"\u6700\u5927\u5927\u5c0f (MB)", maxWidthLabel:"\u6700\u5927\u5bbd\u5ea6 (px)",
    compressBtn:"\u538b\u7f29", processing:"\u5904\u7406\u4e2d",
    beforeLabel:"\u538b\u7f29\u524d", afterLabel:"\u538b\u7f29\u540e",
    savedLabel:"\u8282\u7701\u7a7a\u95f4", downloadBtn:"\u4e0b\u8f7d",
    done:"\u5b8c\u6210\uff01", noFile:"\u8bf7\u62d6\u653e\u56fe\u7247\u3002",
    avifNotSupported:"AVIF\u4e0d\u652f\u6301" }
};

var curLang = detectLang();
var T = DICT[curLang] || DICT.en;

/* DOM HELPERS */
function $(id) { return document.getElementById(id) }
function setStatus(html) { $('status').innerHTML = html }
function formatBytes(b) {
  if (b < 1024) return b + ' B';
  if (b < 1048576) return (b / 1024).toFixed(1) + ' KB';
  return (b / 1048576).toFixed(2) + ' MB';
}

/* AVIF SUPPORT CHECK */
var avifSupported = false;
(function checkAvif() {
  var img = new Image();
  img.onload = function () { avifSupported = img.width > 0; buildFormatSelect() };
  img.onerror = function () { avifSupported = false; buildFormatSelect() };
  img.src = 'data:image/avif;base64,AAAAIGZ0eXBhdmlmAAAAAGF2aWZtaWYxbWlhZk1BMUIAAADybWV0YQAAAAAAAAAoaGRscgAAAAAAAAAAcGljdAAAAAAAAAAAAAAAAGxpYmF2aWYAAAAADnBpdG0AAAAAAAEAAAAeaWxvYwAAAABEAAABAAEAAAABAAABGgAAAB0AAAAoaWluZgAAAAAAAQAAABppbmZlAgAAAAABAABhdjAxQ29sb3IAAAAAamlwcnAAAABLaXBjbwAAABRpc3BlAAAAAAAAAAIAAAACAAAAEHBpeGkAAAAAAwgICAAAAAxhdjFDgQ0MAAAAABNjb2xybmNseAACAAIAAYAAAAAXaXBtYQAAAAAAAAABAAEEAQKDBAAAACVtZGF0EgAKBDgABokyCRAAAAAP+I9ngw==';
})();

function buildFormatSelect() {
  var sel = $('formatSelect'); sel.innerHTML = '';
  var formats = [
    { value: 'keep', label: T.optKeep },
    { value: 'jpeg', label: 'JPEG' },
    { value: 'png',  label: 'PNG' },
    { value: 'webp', label: 'WebP' }
  ];
  if (avifSupported) formats.push({ value: 'avif', label: 'AVIF' });
  formats.forEach(function (f) {
    var opt = document.createElement('option');
    opt.value = f.value; opt.textContent = f.label; sel.appendChild(opt);
  });
}

/* APPLY LANGUAGE */
$('subtitle').textContent = T.subtitle;
$('dropLabel').textContent = T.dropLabel;
$('dropHint').textContent  = T.dropHint;
$('formatLabel').textContent  = T.formatLabel;
$('qualityLabel').textContent = T.qualityLabel;
$('maxSizeLabel').textContent = T.maxSizeLabel;
$('maxWidthLabel').textContent = T.maxWidthLabel;
$('compressBtn').textContent  = T.compressBtn;
$('beforeLabel').textContent  = T.beforeLabel;
$('afterLabel').textContent   = T.afterLabel;
$('savedLabel').textContent   = T.savedLabel;
$('downloadBtn').textContent  = T.downloadBtn;
buildFormatSelect();

/* STATE */
var selectedFile = null;
var origWidth = 0, origHeight = 0;

/* QUALITY SLIDER */
$('qualitySlider').addEventListener('input', function () { $('qualityVal').textContent = this.value });

/* DRAG & DROP */
var dz = $('dropzone');
dz.addEventListener('dragover', function (e) { e.preventDefault(); dz.classList.add('dragover') });
dz.addEventListener('dragleave', function () { dz.classList.remove('dragover') });
dz.addEventListener('drop', function (e) {
  e.preventDefault(); dz.classList.remove('dragover');
  if (e.dataTransfer.files.length) handleFile(e.dataTransfer.files[0]);
});
$('fileInput').addEventListener('change', function () { if (this.files.length) handleFile(this.files[0]) });

function handleFile(file) {
  if (!file.type.match(/^image\/(png|jpeg|webp|avif)$/)) return;
  selectedFile = file; $('compressBtn').disabled = false;
  var reader = new FileReader();
  reader.onload = function (e) {
    var img = new Image();
    img.onload = function () {
      origWidth = img.naturalWidth; origHeight = img.naturalHeight;
      $('previewDim').textContent = origWidth + ' \u00d7 ' + origHeight + ' px';
    };
    img.src = e.target.result;
    $('previewImg').src = e.target.result;
    $('preview').style.display = 'block';
    $('previewName').textContent = file.name + ' (' + formatBytes(file.size) + ')';
  };
  reader.readAsDataURL(file);
  $('results').classList.remove('visible'); $('downloadBtn').classList.remove('visible'); setStatus('');
}

/* COMPRESS */
$('compressBtn').addEventListener('click', async function () {
  if (!selectedFile) { setStatus(T.noFile); return }
  var btn = $('compressBtn'); btn.disabled = true; dz.classList.add('processing');
  setStatus(T.processing + '<span class="blink">...</span>');

  var quality = parseInt($('qualitySlider').value, 10) / 100;
  var format  = $('formatSelect').value;
  var maxMB   = parseFloat($('maxSizeInput').value) || 10;
  var maxW    = parseInt($('maxWidthInput').value, 10) || 4096;

  var options = { maxSizeMB: maxMB, maxWidthOrHeight: maxW, initialQuality: quality,
    useWebWorker: true, preserveExif: false };

  var mimeMap = { jpeg:'image/jpeg', png:'image/png', webp:'image/webp', avif:'image/avif' };
  if (format !== 'keep') {
    if (format === 'avif' && !avifSupported) {
      setStatus(T.avifNotSupported); btn.disabled = false; dz.classList.remove('processing'); return;
    }
    options.fileType = mimeMap[format];
  }
  if (format === 'png') options.fileType = 'image/png';

  try {
    var compressed = await imageCompression(selectedFile, options);
    var origSize = selectedFile.size, compSize = compressed.size;
    var saved = origSize > 0 ? Math.round((1 - compSize / origSize) * 100) : 0;
    if (saved < 0) saved = 0;
    $('beforeSize').textContent = formatBytes(origSize);
    $('beforeDim').textContent  = origWidth + ' \u00d7 ' + origHeight;
    var compURL = URL.createObjectURL(compressed);
    var tempImg = new Image();
    tempImg.onload = function () {
      $('afterDim').textContent = tempImg.naturalWidth + ' \u00d7 ' + tempImg.naturalHeight;
    };
    tempImg.src = compURL;
    $('afterSize').textContent = formatBytes(compSize);
    $('savedPct').textContent  = saved + '%';
    $('results').classList.add('visible');
    var ext = format === 'keep' ? selectedFile.name.split('.').pop() : format;
    var dlName = selectedFile.name.replace(/\.[^.]+$/, '') + '-compressed.' + ext;
    var dlBtn = $('downloadBtn'); dlBtn.href = compURL; dlBtn.download = dlName;
    dlBtn.classList.add('visible');
    setStatus(T.done);
  } catch (e) { setStatus('Error: ' + e.message) }
  dz.classList.remove('processing'); btn.disabled = false;
});
</script>
<script>
/* AUTO-RESIZE SENDER */
(function () {
  function sendHeight() { window.parent.postMessage({ type:'setHeight', height:document.body.scrollHeight }, '*') }
  document.documentElement.style.height = 'auto';
  document.body.style.height = 'auto';
  document.body.style.minHeight = '0';
  window.addEventListener('load', sendHeight);
  window.addEventListener('resize', sendHeight);
  new MutationObserver(sendHeight).observe(document.body, { subtree:true, childList:true });
})();
</script>
</body>
</html>
```

---

## 4. Content Structure — English Front Matter

| Path | Title | Description |
|---|---|---|
| `content/about/index.md` | About Me | Federico Sella - Security Developer and SOC Analyst. Transitioning from 7+ years in CNC Automation (Fanuc/Selca) to Offensive Security and Red Teaming. |
| **Games** | | |
| `content/games/_index.md` | Games | Browser games, CTF challenges and interactive coding puzzles |
| `content/games/deploy-on-friday/index.md` | Deploy on Friday | Can you keep production alive? An endless runner for developers. |
| `content/games/example-game/index.md` | Example Browser Game | A demonstration of how to create browser-based games |
| `content/games/sudo-type/index.md` | Sudo Type | Defend your mainframe by typing commands. A retro hacker typing defense game. |
| **Guides** | | |
| `content/guides/_index.md` | Guides | In-depth tutorials on AI, cybersecurity, Linux, and software development. |
| `content/guides/deepseek-vs-chatgpt/index.md` | DeepSeek vs ChatGPT | A deep-dive comparison of DeepSeek-V3 and GPT-4o covering architecture, pricing, benchmarks, privacy, and censorship. |
| `content/guides/local-ai-setup-ollama/index.md` | Stop Paying for AI: Run DeepSeek & Llama 3 Locally for Free | Learn how to run powerful AI models like DeepSeek and Llama 3 on your own PC for free using Ollama. |
| **News** | | |
| `content/news/_index.md` | Tech News | Latest news and insights from the cybersecurity and technology world |
| `content/news/2026/01/` | *(~400 articles)* | Mix of EN cybersecurity news and IT Italian tech news |
| **Projects** | | |
| `content/projects/_index.md` | My Projects | Coding projects, Tools, and Browser Games developed from scratch. |
| `content/projects/doc/index.md` | Personal Portfolio & Blog | Development of a high-performance static site using Hugo and GitHub Actions. |
| `content/projects/lyric-video-generator/index.md` | FLAC Lyric Video Generator | A specialized automation tool for audiophiles to enjoy lossless FLAC audio with synchronized lyrics on in-car systems. |
| `content/projects/penta-framework/index.md` | PentaFramework | *(Pentesting framework — no description)* |
| `content/projects/zendesk-soc-hunter/index.md` | Zendesk SOC Hunter | The browser extension for SOC Analysts and Helpdesk support using Zendesk |
| **Tools** | | |
| `content/tools/_index.md` | Tools | Interactive cybersecurity and development tools - all client-side, no data sent to servers |
| `content/tools/base64-converter/index.md` | Base64 Encoder/Decoder | Encode and decode text to/from Base64 format with UTF-8 support |
| `content/tools/caesar-cipher/index.md` | Caesar Cipher | Encrypt and decrypt text using the classic Caesar cipher with customizable shift key |
| `content/tools/easy-cron/index.md` | EasyCron: Visual Cron Job Generator | The easiest way to create Linux Cron jobs. Visual editor, crontab explainer, and next-run calculator. |
| `content/tools/example-tool/index.md` | Example Interactive Tool | A demonstration of how to create interactive tools |
| `content/tools/freelance-calculator/index.md` | RateMate: Freelance Hourly Rate Calculator | Calculate your ideal freelance hourly rate based on salary goals, taxes, and business expenses. |
| `content/tools/glitch-forge/index.md` | GlitchForge: Glitch Art Generator | Turn your photos into cyberpunk art. Free, offline, privacy-focused glitch image editor. |
| `content/tools/hash-generator/index.md` | Hash Generator | Generate cryptographic hashes (MD5, SHA-1, SHA-256, SHA-512) using Web Crypto API |
| `content/tools/netguard/index.md` | NetGuard: Check My IP Address & Browser Leak Test | Is your browser leaking data? Check your public IP, WebRTC leak status, GPU fingerprint, and digital identity. |
| `content/tools/pass-fort/index.md` | PassFort: Secure Password Generator & Strength Checker | Create unhackable passwords and audit your security in seconds. Entropy calculator, brute-force crack time estimator. |
| `content/tools/pixel-shrink/index.md` | PixelShrink | Compress PNG, JPG, and WebP images locally in your browser. No uploads, 100% privacy. |
| `content/tools/reflex-grid/index.md` | ReflexGrid: Free Aim Trainer & Reaction Time Test | Test your mouse accuracy and reaction time. Built for FPS gamers — Valorant, CS2, CoD. |
| `content/tools/zen-focus/index.md` | ZenFocus: Ambient Noise Mixer & Pomodoro | Boost your productivity with custom ambient sounds and a focus timer. |
| **Writeups** | | |
| `content/writeups/_index.md` | CTF Writeups | Detailed walkthroughs of Capture The Flag challenges and HackTheBox machines. |

### Language Coverage per Section

| Section | Languages Available |
|---|---|
| About | en, it, es, fr, de, pt, ru, ja, ko, zh-cn, ar, hi |
| Games | en, it, es, fr, de, pt, ru, ja, ko, zh-cn, ar, hi |
| Guides | en, it, es, fr, de, pt, ru, ja, ko, zh-cn, ar, hi |
| News | en, it |
| Tools | en, it, es, fr, de, pt, ru, ja, ko, zh-cn, ar, hi |
| Projects | en (+ some localized) |
| Writeups | en |

---

*End of PROJECT_SUMMARY.md*
