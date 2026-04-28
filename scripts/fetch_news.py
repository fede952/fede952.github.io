#!/usr/bin/env python3
"""
News Fetching Script — Federico Sella Tech Portal

Pipeline:
  RSS fetch -> niche filter (cybersec/devops; reject affiliate)
            -> dedup against cache
            -> rank, pick the daily Top-N
            -> DeepSeek enrich (Cyber-Report + Netrunner Insight, JSON)
            -> DeepSeek translate JSON into 11 other languages
            -> render slug.md (EN canonical) + slug.{lang}.md siblings
"""

import hashlib
import json
import os
import sys
import time
from datetime import date, datetime, timezone
from pathlib import Path
from urllib.parse import urlparse

import feedparser
from bs4 import BeautifulSoup
from slugify import slugify

try:
    from openai import OpenAI
except ImportError:
    print("[FATAL] Missing dependency: openai. Run: pip install -r scripts/requirements.txt")
    sys.exit(2)

# ============================================
# CONFIGURATION
# ============================================

BASE_DIR = Path(__file__).parent.parent
CONTENT_DIR = BASE_DIR / "content" / "news"
CACHE_FILE = BASE_DIR / "scripts" / ".news_cache.json"

DEEPSEEK_API_KEY = os.environ.get("DEEPSEEK_API_KEY")
DEEPSEEK_BASE_URL = "https://api.deepseek.com"
DEEPSEEK_MODEL = "deepseek-chat"
DRY_RUN = os.environ.get("DRY_RUN") == "1"

# (code, English name, suffix). English's suffix is None — canonical file is slug.md.
LANGUAGES = [
    ("en",    "English",            None),
    ("it",    "Italian",            "it"),
    ("es",    "Spanish",            "es"),
    ("zh-cn", "Simplified Chinese", "zh-cn"),
    ("hi",    "Hindi",              "hi"),
    ("ar",    "Arabic",             "ar"),
    ("pt",    "Portuguese",         "pt"),
    ("fr",    "French",             "fr"),
    ("de",    "German",             "de"),
    ("ja",    "Japanese",           "ja"),
    ("ru",    "Russian",            "ru"),
    ("ko",    "Korean",             "ko"),
]

FEEDS = [
    "https://feeds.feedburner.com/TheHackersNews",
    "https://www.bleepingcomputer.com/feed/",
    "https://www.wired.com/feed/category/security/latest/rss",
    "https://www.redhotcyber.com/feed/",
    "https://cert-agid.gov.it/feed/",
    "https://www.cybersecurity360.it/feed/",
    "https://www.cisa.gov/cybersecurity-advisories/all.xml",
    "https://krebsonsecurity.com/feed/",
    "https://www.darkreading.com/rss.xml",
]

# Cybersecurity360 must pass strict keyword check; others are trusted.
STRICT_FILTER_DOMAINS = {"cybersecurity360.it"}

RELEVANT_KEYWORDS = {
    "cve", "vulnerability", "vulnerabilità", "exploit", "rce", "zero-day",
    "zeroday", "0-day", "ransomware", "malware", "phishing", "apt",
    "breach", "leak", "data leak", "patch", "advisory", "cisa", "kev",
    "supply chain", "supply-chain", "backdoor", "trojan", "botnet", "ddos",
    "siem", "soc", "edr", "xdr", "ioc", "threat actor", "mitre", "att&ck",
    "owasp", "nis2", "dora", "gdpr", "cybersecurity", "cyber security",
    "sicurezza informatica", "incident response", "red team", "blue team",
    "pentest", "kubernetes", "docker", "cloud security", "iam", "mfa",
    "ai security", "llm security", "prompt injection",
}

# Affiliate / shopping noise — hard reject for ALL feeds.
REJECT_KEYWORDS = {
    " sconto", "offerta", "amazon", "ebay", "promo", "coupon",
    "minimo storico", "in offerta", "deal", "black friday",
    "abbonamento", "abbonati", "regalo", "saldi",
    "smartphone in offerta", "prezzo migliore", "miglior prezzo",
    "buono sconto", "cashback",
}

DAILY_TOP_N = 5
MAX_CANDIDATES_PER_FEED = 15
# Hard kill-switch: total DeepSeek calls allowed per UTC day across all runs.
# 5 articles * 12 languages = 60 calls baseline; 100 leaves headroom for retries.
MAX_DAILY_LLM_CALLS = 100

# Localized "read more" labels — deterministic, no LLM call needed.
READ_MORE_LABEL = {
    "en":    "Read full article on {source}",
    "it":    "Leggi l'articolo completo su {source}",
    "es":    "Leer el artículo completo en {source}",
    "zh-cn": "在 {source} 上阅读全文",
    "hi":    "पूरा लेख {source} पर पढ़ें",
    "ar":    "اقرأ المقال كاملاً على {source}",
    "pt":    "Leia o artigo completo em {source}",
    "fr":    "Lire l'article complet sur {source}",
    "de":    "Vollständigen Artikel auf {source} lesen",
    "ja":    "完全な記事を {source} で読む",
    "ru":    "Читать полную статью на {source}",
    "ko":    "{source}에서 전체 기사 읽기",
}

ENRICH_SCHEMA_HINT = {
    "headline": "string, max 90 chars, catchy English",
    "deck": "string, 100-160 chars, English meta-description",
    "cyber_report": {
        "severity": "one of: Critical | High | Medium | Low | Info",
        "target": "string, max 60 chars",
        "cve": "string like CVE-YYYY-NNNNN or null",
        "cvss": "float 0.0-10.0 or null",
        "kev": "true | false | null",
    },
    "body_paragraphs": "list of 2-3 strings (English)",
    "netrunner_insight": "string, 2-3 sentences (English)",
}

# ============================================
# UTILITIES
# ============================================

def log(msg: str) -> None:
    print(msg, flush=True)


def load_cache() -> dict:
    if CACHE_FILE.exists():
        try:
            return json.loads(CACHE_FILE.read_text(encoding="utf-8"))
        except Exception as e:
            log(f"[WARN] Could not load cache: {e}")
    return {"processed_urls": [], "processed_ids": [], "daily_published": {}}


def save_cache(cache: dict) -> None:
    try:
        CACHE_FILE.parent.mkdir(parents=True, exist_ok=True)
        CACHE_FILE.write_text(
            json.dumps(cache, ensure_ascii=False, indent=2), encoding="utf-8"
        )
    except Exception as e:
        log(f"[WARN] Could not save cache: {e}")


def clean_html(html_text: str) -> str:
    if not html_text:
        return ""
    soup = BeautifulSoup(html_text, "html.parser")
    for tag in soup(["script", "style"]):
        tag.decompose()
    return " ".join(soup.get_text(separator=" ").split())


def article_id(url: str, title: str) -> str:
    return hashlib.md5(f"{url}_{title}".encode("utf-8")).hexdigest()


def source_name_from_url(url: str) -> str:
    u = url.lower()
    if "thehackersnews" in u or "feedburner" in u: return "The Hacker News"
    if "bleepingcomputer" in u:   return "BleepingComputer"
    if "wired" in u:              return "Wired Security"
    if "redhotcyber" in u:        return "Red Hot Cyber"
    if "cert-agid" in u:          return "CERT-AgID"
    if "cybersecurity360" in u:   return "Cybersecurity360"
    if "cisa.gov" in u:           return "CISA"
    if "krebsonsecurity" in u:    return "Krebs on Security"
    if "darkreading" in u:        return "Dark Reading"
    domain = urlparse(url).netloc.replace("www.", "")
    return domain.split(".")[0].title()


def domain_of(url: str) -> str:
    return urlparse(url).netloc.replace("www.", "")


def relevance_score(title: str, summary: str, feed_url: str) -> tuple[bool, int]:
    """Return (passes_filter, score). Higher = more relevant."""
    text = f"{title} {summary}".lower()
    domain = domain_of(feed_url)

    # Hard reject affiliate/shopping noise across ALL feeds.
    if any(k in text for k in REJECT_KEYWORDS):
        return False, 0

    relevant_hits = sum(1 for k in RELEVANT_KEYWORDS if k in text)

    # Cybersecurity360 must hit at least one cybersec keyword.
    if domain in STRICT_FILTER_DOMAINS and relevant_hits == 0:
        return False, 0

    base = 0 if domain in STRICT_FILTER_DOMAINS else 1
    return True, base + relevant_hits


# ============================================
# DEEPSEEK CLIENT
# ============================================

class BudgetExceeded(Exception):
    """Raised when the daily LLM call cap has been reached."""


class LLMBudget:
    """Tracks DeepSeek API calls per UTC day, persisted in the cache file."""

    def __init__(self, cache: dict, today: str, cap: int):
        self.cache = cache
        self.today = today
        self.cap = cap

    @property
    def used(self) -> int:
        return self.cache.get("daily_llm_calls", {}).get(self.today, 0)

    def check_and_bump(self) -> None:
        if self.used >= self.cap:
            raise BudgetExceeded(
                f"daily LLM call cap reached: {self.used}/{self.cap}"
            )
        d = self.cache.setdefault("daily_llm_calls", {})
        d[self.today] = self.used + 1
        if len(d) > 30:
            for k in sorted(d.keys())[:-30]:
                del d[k]


def make_client() -> OpenAI:
    if not DEEPSEEK_API_KEY:
        log("[FATAL] DEEPSEEK_API_KEY environment variable is not set.")
        sys.exit(2)
    return OpenAI(api_key=DEEPSEEK_API_KEY, base_url=DEEPSEEK_BASE_URL)


def deepseek_json(client: OpenAI, system: str, user: str, *,
                  budget: LLMBudget, retries: int = 3) -> dict:
    """Call DeepSeek with JSON mode; parse and return the dict. Retries on transient failure.

    Each attempt counts against the daily budget. Raises BudgetExceeded when the
    cap is reached — the caller decides whether to skip or abort.
    """
    last_err: Exception | None = None
    for attempt in range(1, retries + 1):
        budget.check_and_bump()  # raises BudgetExceeded if cap hit
        try:
            resp = client.chat.completions.create(
                model=DEEPSEEK_MODEL,
                messages=[
                    {"role": "system", "content": system},
                    {"role": "user", "content": user},
                ],
                response_format={"type": "json_object"},
                temperature=0.3,
                max_tokens=2000,
            )
            content = resp.choices[0].message.content or ""
            return json.loads(content)
        except json.JSONDecodeError as e:
            last_err = e
            log(f"[WARN] JSON decode failed (attempt {attempt}): {e}")
        except Exception as e:
            last_err = e
            log(f"[WARN] DeepSeek call failed (attempt {attempt}): {e}")
        time.sleep(2 * attempt)
    raise RuntimeError(f"DeepSeek call exhausted retries: {last_err}")


# ============================================
# ENRICH + TRANSLATE
# ============================================

ENRICH_SYSTEM = (
    "You are a senior cybersecurity analyst writing for technical English readers "
    "(SOC analysts, DevSecOps engineers, red/blue teamers). Given a news item, "
    "produce a structured JSON object. Be factual: never invent CVE identifiers, "
    "CVSS scores, vendor names, attribution, dates, or victim counts that are not "
    "present in the input. If a structured field cannot be confidently determined "
    "from the input, return null. Severity classification must be conservative — "
    "use Info when uncertain."
)


def enrich(client: OpenAI, item: dict, *, budget: LLMBudget) -> dict:
    user = (
        "Produce a JSON object for the following news item.\n\n"
        f"INPUT:\n{json.dumps(item, ensure_ascii=False, indent=2)}\n\n"
        f"SCHEMA (fields and types):\n{json.dumps(ENRICH_SCHEMA_HINT, indent=2)}\n\n"
        "RULES:\n"
        "- headline: ≤90 chars, English, catchy; mention CVE if present in input.\n"
        "- deck: 100–160 chars, English, suitable as meta description.\n"
        "- cyber_report.cve: ONLY if a CVE-YYYY-NNNNN identifier appears verbatim "
        "in input, otherwise null.\n"
        "- cyber_report.cvss: ONLY if explicitly stated, otherwise null.\n"
        "- cyber_report.kev: true ONLY if input references CISA KEV catalog, "
        "otherwise null.\n"
        "- cyber_report.target: short noun phrase (e.g. 'Apache ActiveMQ servers').\n"
        "- body_paragraphs: 2–3 substantive English paragraphs of analytical "
        "prose. Synthesize from the summary; do not fabricate technical details.\n"
        "- netrunner_insight: 2–3 sentences. Opinionated, practical takeaway for "
        "SOC analysts and DevSecOps engineers.\n\n"
        "Return ONLY the JSON object."
    )
    return deepseek_json(client, ENRICH_SYSTEM, user, budget=budget)


TRANSLATE_SYSTEM = (
    "You are a professional technical translator specialising in cybersecurity. "
    "You translate ONLY the values listed below, preserving the exact JSON shape "
    "and all other fields untouched. You never translate vendor or product names, "
    "CVE identifiers, CVSS numbers, severity enum values, booleans, or URLs."
)


def translate(client: OpenAI, enriched: dict, target_lang_name: str, *,
              budget: LLMBudget) -> dict:
    user = (
        f"Translate the following JSON into {target_lang_name}, returning the "
        "same JSON shape.\n\n"
        "PRESERVE EXACTLY (do not translate):\n"
        "- All JSON keys.\n"
        "- cyber_report.cve, cyber_report.cvss, cyber_report.kev, "
        "cyber_report.severity (keep enum value in English).\n"
        "- All vendor / product names appearing inside any field (Apache, "
        "ActiveMQ, Microsoft, Chrome, BleepingComputer, etc.).\n"
        "- Any URLs.\n\n"
        "TRANSLATE: headline, deck, cyber_report.target (descriptive parts only — "
        "keep brand names in source script), each item of body_paragraphs, "
        "netrunner_insight. Adapt idioms naturally; do not translate literally.\n\n"
        f"INPUT:\n{json.dumps(enriched, ensure_ascii=False, indent=2)}\n\n"
        "Return ONLY the translated JSON object."
    )
    return deepseek_json(client, TRANSLATE_SYSTEM, user, budget=budget)


# ============================================
# RENDER
# ============================================

def yaml_value(v) -> str:
    """Emit a JSON-encoded value that is also valid YAML."""
    if v is None:                     return "null"
    if isinstance(v, bool):           return "true" if v else "false"
    if isinstance(v, (int, float)):   return str(v)
    if isinstance(v, list):           return json.dumps(v, ensure_ascii=False)
    return json.dumps(str(v), ensure_ascii=False)


def render_markdown(payload: dict, *, lang: str, source_name: str,
                    original_url: str, date_obj: datetime, slug: str) -> str:
    cr = payload.get("cyber_report") or {}
    severity = cr.get("severity") or "Info"
    target   = cr.get("target")
    cve      = cr.get("cve")
    cvss     = cr.get("cvss")
    kev      = cr.get("kev")

    fm = {
        "title": payload.get("headline") or "Untitled",
        "date": date_obj.strftime("%Y-%m-%dT%H:%M:%S"),
        "lang": lang,
        "translationKey": slug,
        "author": "NewsBot (Validated by Federico Sella)",
        "description": payload.get("deck") or "",
        "original_url": original_url,
        "source": source_name,
        "severity": severity,
        "target": target,
        "cve": cve,
        "cvss": cvss,
        "kev": kev,
        "tags": ["news", "cybersecurity"],
        "news-categories": ["cybersecurity"],
        "layout": "news",
        "draft": False,
    }
    fm_lines = ["---"] + [f"{k}: {yaml_value(v)}" for k, v in fm.items()] + ["---"]
    frontmatter = "\n".join(fm_lines)

    cr_params = [f'severity="{severity}"', f'source="{source_name}"']
    if target:           cr_params.append(f'target={json.dumps(str(target), ensure_ascii=False)}')
    if cve:              cr_params.append(f'cve="{cve}"')
    if cvss is not None: cr_params.append(f'cvss="{cvss}"')
    if kev is not None:  cr_params.append(f'kev="{"true" if kev else "false"}"')
    cyber_report_sc = "{{< cyber-report " + " ".join(cr_params) + " >}}"

    paragraphs = payload.get("body_paragraphs") or []
    insight    = (payload.get("netrunner_insight") or "").strip()

    parts: list[str] = [(payload.get("deck") or "").strip(), cyber_report_sc]
    if paragraphs:
        parts.append((paragraphs[0] or "").strip())
    parts.append("{{< ad-banner >}}")
    for p in paragraphs[1:]:
        if p and p.strip():
            parts.append(p.strip())
    if insight:
        parts.append("{{< netrunner-insight >}}")
        parts.append(insight)
        parts.append("{{< /netrunner-insight >}}")
    parts.append("---")
    read_more = READ_MORE_LABEL.get(lang, READ_MORE_LABEL["en"]).format(source=source_name)
    parts.append(f"**[{read_more} ›]({original_url})**")

    body = "\n\n".join(p for p in parts if p)
    return frontmatter + "\n\n" + body + "\n"


# ============================================
# PIPELINE
# ============================================

def collect_candidates(cache: dict) -> list[dict]:
    candidates: list[dict] = []
    seen_urls = set(cache.get("processed_urls", []))
    seen_ids  = set(cache.get("processed_ids", []))

    for feed_url in FEEDS:
        log(f"[FEED] {feed_url}")
        try:
            feed = feedparser.parse(feed_url)
        except Exception as e:
            log(f"  [ERR] {e}")
            continue
        if feed.bozo:
            log(f"  [WARN] Feed parse warning: {feed.bozo_exception}")
        if not feed.entries:
            log("  [WARN] No entries.")
            continue

        for entry in feed.entries[:MAX_CANDIDATES_PER_FEED]:
            url   = entry.get("link", "")
            title = clean_html(entry.get("title", ""))
            if not url or not title:
                continue
            aid = article_id(url, title)
            if url in seen_urls or aid in seen_ids:
                continue
            summary = clean_html(entry.get("summary", entry.get("description", "")))
            ok, score = relevance_score(title, summary, feed_url)
            if not ok:
                continue
            if hasattr(entry, "published_parsed") and entry.published_parsed:
                dt = datetime(*entry.published_parsed[:6])
            else:
                dt = datetime.utcnow()
            candidates.append({
                "id": aid,
                "url": url,
                "title": title,
                "summary": summary[:1500],
                "feed_url": feed_url,
                "source_name": source_name_from_url(feed_url),
                "score": score,
                "published_at": dt,
            })
    return candidates


def select_top(candidates: list[dict], n: int) -> list[dict]:
    candidates.sort(key=lambda c: (c["score"], c["published_at"]), reverse=True)
    return candidates[:n]


def daily_remaining(cache: dict, today: str, cap: int) -> int:
    return max(0, cap - cache.get("daily_published", {}).get(today, 0))


def bump_daily(cache: dict, today: str) -> None:
    dp = cache.setdefault("daily_published", {})
    dp[today] = dp.get(today, 0) + 1
    if len(dp) > 30:
        for k in sorted(dp.keys())[:-30]:
            del dp[k]


def publish_article(client: OpenAI | None, candidate: dict, cache: dict,
                    budget: LLMBudget) -> bool:
    log(f"\n[PUBLISH] {candidate['title'][:80]}  (score={candidate['score']})")

    if DRY_RUN:
        enriched = {
            "headline": candidate["title"],
            "deck": candidate["summary"][:160],
            "cyber_report": {"severity": "Info", "target": None,
                             "cve": None, "cvss": None, "kev": None},
            "body_paragraphs": [candidate["summary"][:400]],
            "netrunner_insight": "(dry-run insight)",
        }
    else:
        try:
            enriched = enrich(client, {
                "source_name":  candidate["source_name"],
                "source_url":   candidate["url"],
                "title":        candidate["title"],
                "summary":      candidate["summary"],
                "published_at": candidate["published_at"].isoformat(),
            }, budget=budget)
        except BudgetExceeded:
            raise  # propagate to main loop — abort the run
        except Exception as e:
            log(f"  [SKIP] Enrichment failed: {e}")
            return False

    headline = enriched.get("headline") or candidate["title"]
    slug = (slugify(headline) or slugify(candidate["title"]))[:100]
    if not slug:
        log("  [SKIP] Empty slug after slugify.")
        return False

    date_obj = candidate["published_at"]
    out_dir = CONTENT_DIR / date_obj.strftime("%Y") / date_obj.strftime("%m")
    out_dir.mkdir(parents=True, exist_ok=True)

    en_path = out_dir / f"{slug}.md"
    if en_path.exists():
        log(f"  [SKIP] EN file already exists: {en_path.name}")
        return False

    en_path.write_text(
        render_markdown(enriched, lang="en", source_name=candidate["source_name"],
                        original_url=candidate["url"], date_obj=date_obj, slug=slug),
        encoding="utf-8",
    )
    log(f"  [OK] en  -> {en_path.relative_to(BASE_DIR)}")

    for code, name, suffix in LANGUAGES:
        if code == "en":
            continue
        out_path = out_dir / f"{slug}.{suffix}.md"
        if out_path.exists():
            log(f"  [SKIP] {code} exists.")
            continue
        try:
            translated = enriched if DRY_RUN else translate(
                client, enriched, name, budget=budget
            )
            out_path.write_text(
                render_markdown(translated, lang=code,
                                source_name=candidate["source_name"],
                                original_url=candidate["url"],
                                date_obj=date_obj, slug=slug),
                encoding="utf-8",
            )
            log(f"  [OK] {code:5} -> {out_path.relative_to(BASE_DIR)}")
        except BudgetExceeded as e:
            log(f"  [BUDGET] Stopping further translations: {e}")
            break
        except Exception as e:
            log(f"  [WARN] {code} translation failed: {e}")
            continue

    cache.setdefault("processed_urls", []).append(candidate["url"])
    cache.setdefault("processed_ids",  []).append(candidate["id"])
    return True


# ============================================
# MAIN
# ============================================

def main() -> int:
    log("=" * 60)
    log("NEWS FETCHING SCRIPT — Federico Sella Tech Portal")
    log("=" * 60)
    log(f"Start: {datetime.now(timezone.utc).strftime('%Y-%m-%dT%H:%M:%SZ')}")
    log(f"Daily cap: {DAILY_TOP_N}  |  Languages: {len(LANGUAGES)}  |  Dry-run: {DRY_RUN}")

    CONTENT_DIR.mkdir(parents=True, exist_ok=True)

    cache = load_cache()
    today_key = date.today().isoformat()
    remaining = daily_remaining(cache, today_key, DAILY_TOP_N)
    log(f"Already published today: {DAILY_TOP_N - remaining}/{DAILY_TOP_N}")
    if remaining == 0:
        log("Daily quota already reached — nothing to do.")
        save_cache(cache)
        return 0

    candidates = collect_candidates(cache)
    log(f"\nCandidates after filter: {len(candidates)}")
    selected = select_top(candidates, remaining)
    log(f"Selected for publish: {len(selected)}")

    client = None if DRY_RUN else make_client()
    budget = LLMBudget(cache, today_key, MAX_DAILY_LLM_CALLS)
    log(f"LLM call budget: {budget.used}/{budget.cap} used today")

    published = 0
    for cand in selected:
        if remaining <= 0:
            break
        try:
            ok = publish_article(client, cand, cache, budget)
        except BudgetExceeded as e:
            log(f"[BUDGET] {e} — stopping run.")
            break
        if ok:
            bump_daily(cache, today_key)
            published += 1
            remaining -= 1
            save_cache(cache)  # persist budget + dedup state per article

    save_cache(cache)

    log("=" * 60)
    log(f"Published this run: {published}")
    log(f"End: {datetime.now(timezone.utc).strftime('%Y-%m-%dT%H:%M:%SZ')}")
    log("=" * 60)
    return 0 if published > 0 else 1


if __name__ == "__main__":
    sys.exit(main())
