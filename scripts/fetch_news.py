#!/usr/bin/env python3
"""
News Fetching Script for Federico Sella Tech Portal
Fetches news from RSS feeds and generates Hugo-compatible markdown files
Supports separate English and Italian sources
"""

import os
import sys
from datetime import datetime
from pathlib import Path
import feedparser
import requests
from slugify import slugify
from bs4 import BeautifulSoup
import hashlib
import json

# ============================================
# CONFIGURATION
# ============================================

# Base paths
BASE_DIR = Path(__file__).parent.parent
CONTENT_DIR = BASE_DIR / "content" / "news"
CACHE_FILE = BASE_DIR / "scripts" / ".news_cache.json"

# RSS Feed Sources
SOURCES_EN = [
    'https://feeds.feedburner.com/TheHackersNews',
    'https://www.bleepingcomputer.com/feed/',
    'https://www.wired.com/feed/category/security/latest/rss'
]

SOURCES_IT = [
    'https://www.punto-informatico.it/feed/',
    'https://www.cybersecurity360.it/feed/'
]

# Limits
MAX_ARTICLES_PER_SOURCE = 5

# ============================================
# UTILITY FUNCTIONS
# ============================================

def load_cache():
    """Load processed articles cache to avoid duplicates"""
    if CACHE_FILE.exists():
        try:
            with open(CACHE_FILE, 'r', encoding='utf-8') as f:
                return json.load(f)
        except Exception as e:
            print(f"Warning: Could not load cache: {e}")
            return {"processed_urls": [], "processed_ids": []}
    return {"processed_urls": [], "processed_ids": []}

def save_cache(cache_data):
    """Save processed articles cache"""
    try:
        CACHE_FILE.parent.mkdir(parents=True, exist_ok=True)
        with open(CACHE_FILE, 'w', encoding='utf-8') as f:
            json.dump(cache_data, f, ensure_ascii=False, indent=2)
    except Exception as e:
        print(f"Warning: Could not save cache: {e}")

def clean_html(html_text):
    """Remove HTML tags from text and clean it up"""
    if not html_text:
        return ""

    soup = BeautifulSoup(html_text, 'html.parser')

    # Remove script and style elements
    for script in soup(["script", "style"]):
        script.decompose()

    # Get text
    text = soup.get_text()

    # Clean up whitespace
    lines = (line.strip() for line in text.splitlines())
    chunks = (phrase.strip() for line in lines for phrase in line.split("  "))
    text = ' '.join(chunk for chunk in chunks if chunk)

    return text

def generate_article_id(url, title):
    """Generate unique ID for article"""
    content = f"{url}_{title}".encode('utf-8')
    return hashlib.md5(content).hexdigest()

def extract_source_name(feed_url):
    """Extract source name from feed URL"""
    if 'hackernews' in feed_url.lower():
        return "The Hacker News"
    elif 'bleepingcomputer' in feed_url.lower():
        return "BleepingComputer"
    elif 'wired.com' in feed_url.lower():
        return "Wired Security"
    elif 'punto-informatico' in feed_url.lower():
        return "Punto Informatico"
    elif 'cybersecurity360' in feed_url.lower():
        return "Cybersecurity360"
    else:
        # Fallback: extract domain name
        from urllib.parse import urlparse
        domain = urlparse(feed_url).netloc
        return domain.replace('www.', '').split('.')[0].title()

def get_or_create_year_month_dir(date_obj, lang_code=""):
    """Create year/month directory structure"""
    year = date_obj.strftime("%Y")
    month = date_obj.strftime("%m")

    year_month_dir = CONTENT_DIR / year / month
    year_month_dir.mkdir(parents=True, exist_ok=True)

    return year_month_dir

def check_file_exists(year_month_dir, slug, lang_code=""):
    """Check if article file already exists"""
    if lang_code:
        filename = f"{slug}.{lang_code}.md"
    else:
        filename = f"{slug}.md"

    filepath = year_month_dir / filename
    return filepath.exists(), filepath

def categorize_article(title, description):
    """Auto-categorize article based on keywords"""
    text = f"{title} {description}".lower()

    # Cybersecurity keywords
    cybersec_keywords = ['security', 'hack', 'breach', 'vulnerability', 'exploit',
                         'malware', 'ransomware', 'phishing', 'cyber', 'sicurezza']

    # AI/ML keywords
    ai_keywords = ['ai', 'artificial intelligence', 'machine learning', 'ml',
                   'deep learning', 'neural', 'gpt', 'llm']

    # Dev tools keywords
    dev_keywords = ['developer', 'programming', 'code', 'github', 'api',
                    'framework', 'library', 'sviluppo']

    categories = []

    if any(keyword in text for keyword in cybersec_keywords):
        categories.append('cybersecurity')

    if any(keyword in text for keyword in ai_keywords):
        categories.append('ai-ml')

    if any(keyword in text for keyword in dev_keywords):
        categories.append('dev-tools')

    # Default category if none matched
    if not categories:
        categories.append('general')

    return categories

def generate_frontmatter(entry, source_url, lang_code=""):
    """Generate YAML frontmatter for Hugo"""
    # Parse date
    if hasattr(entry, 'published_parsed') and entry.published_parsed:
        date_obj = datetime(*entry.published_parsed[:6])
    else:
        date_obj = datetime.now()

    # Clean title
    title = clean_html(entry.get('title', 'Untitled'))
    # Escape double quotes in title
    title = title.replace('"', '\\"')

    # Clean description
    description = clean_html(entry.get('summary', entry.get('description', '')))
    if len(description) > 300:
        description = description[:297] + "..."
    # Escape double quotes in description
    description = description.replace('"', '\\"')

    # Get original URL
    original_url = entry.get('link', '')

    # Categorize
    categories = categorize_article(title, description)

    # Extract source name
    source_name = extract_source_name(source_url)

    # Build frontmatter
    frontmatter = f"""---
title: "{title}"
date: {date_obj.strftime('%Y-%m-%dT%H:%M:%S')}
author: "NewsBot"
description: "{description}"
original_url: "{original_url}"
source: "{source_name}"
tags: ["news", "tech"]
news-categories: {json.dumps(categories)}
layout: "news"
draft: false
---
"""

    return frontmatter, date_obj, title

def generate_article_body(entry, source_url, lang_code=""):
    """Generate article body content"""
    # Clean summary/description
    if 'summary' in entry:
        content = clean_html(entry.summary)
    elif 'description' in entry:
        content = clean_html(entry.description)
    else:
        content = "No description available."

    # Split into paragraphs (simple approach: split on double newlines or periods)
    paragraphs = content.split('\n\n') if '\n\n' in content else content.split('. ')

    # Rebuild with Hugo ad shortcode after first paragraph
    if len(paragraphs) > 1:
        body = paragraphs[0].strip()
        if not body.endswith('.'):
            body += '.'

        # Add Hugo ad shortcode
        body += '\n\n{{< ad-banner >}}\n\n'

        # Add remaining paragraphs
        body += '\n\n'.join(p.strip() for p in paragraphs[1:] if p.strip())
    else:
        body = content
        body += '\n\n{{< ad-banner >}}'

    # Add source link with language-specific text
    source_name = extract_source_name(source_url)
    original_url = entry.get('link', '')

    if lang_code == 'it':
        read_more_text = f"Leggi l'articolo completo su {source_name} ›"
    else:
        read_more_text = f"Read full article on {source_name} ›"

    body += f'\n\n---\n\n**[{read_more_text}]({original_url})**'

    return body

def fetch_feed(feed_url, lang_code="", cache_data=None):
    """Fetch and parse RSS feed"""
    if cache_data is None:
        cache_data = load_cache()

    print(f"\n{'='*60}")
    print(f"Fetching feed: {feed_url}")
    print(f"Language: {'Italian' if lang_code == 'it' else 'English'}")
    print(f"{'='*60}")

    try:
        # Fetch feed with timeout
        feed = feedparser.parse(feed_url)

        if feed.bozo:
            print(f"Warning: Feed has issues - {feed.bozo_exception}")

        if not feed.entries:
            print("No entries found in feed")
            return 0

        print(f"Found {len(feed.entries)} entries in feed")

        articles_created = 0

        # Process entries (limit to MAX_ARTICLES_PER_SOURCE)
        for entry in feed.entries[:MAX_ARTICLES_PER_SOURCE]:
            try:
                # Generate article ID
                article_url = entry.get('link', '')
                article_title = entry.get('title', '')
                article_id = generate_article_id(article_url, article_title)

                # Check if already processed
                if article_url in cache_data['processed_urls'] or article_id in cache_data['processed_ids']:
                    print(f"  [SKIP] Duplicate: {article_title[:50]}...")
                    continue

                # Generate frontmatter
                frontmatter, date_obj, title = generate_frontmatter(entry, feed_url, lang_code)

                # Generate slug
                slug = slugify(title)
                if len(slug) > 100:
                    slug = slug[:100]

                # Get/create year/month directory
                year_month_dir = get_or_create_year_month_dir(date_obj, lang_code)

                # Check if file exists
                file_exists, filepath = check_file_exists(year_month_dir, slug, lang_code)

                if file_exists:
                    print(f"  [SKIP] File already exists: {filepath.name}")
                    continue

                # Generate body
                body = generate_article_body(entry, feed_url, lang_code)

                # Combine frontmatter + body
                article_content = frontmatter + '\n' + body

                # Write file
                with open(filepath, 'w', encoding='utf-8') as f:
                    f.write(article_content)

                print(f"  [OK] Created: {filepath.relative_to(BASE_DIR)}")

                # Update cache
                cache_data['processed_urls'].append(article_url)
                cache_data['processed_ids'].append(article_id)

                articles_created += 1

            except Exception as e:
                print(f"  [ERROR] Error processing entry: {e}")
                continue

        return articles_created

    except Exception as e:
        print(f"[ERROR] Error fetching feed: {e}")
        return 0

# ============================================
# MAIN FUNCTION
# ============================================

def main():
    """Main execution function"""
    print("\n" + "="*60)
    print("NEWS FETCHING SCRIPT - Federico Sella Tech Portal")
    print("="*60)
    print(f"Start time: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
    print(f"Base directory: {BASE_DIR}")
    print(f"Content directory: {CONTENT_DIR}")
    print(f"Max articles per source: {MAX_ARTICLES_PER_SOURCE}")

    # Ensure content directory exists
    CONTENT_DIR.mkdir(parents=True, exist_ok=True)

    # Load cache
    cache_data = load_cache()
    print(f"\nCache loaded: {len(cache_data['processed_urls'])} articles already processed")

    total_articles = 0

    # Fetch English sources
    print("\n" + "="*60)
    print("PROCESSING ENGLISH SOURCES")
    print("="*60)

    for feed_url in SOURCES_EN:
        articles = fetch_feed(feed_url, lang_code="", cache_data=cache_data)
        total_articles += articles

    # Fetch Italian sources
    print("\n" + "="*60)
    print("PROCESSING ITALIAN SOURCES")
    print("="*60)

    for feed_url in SOURCES_IT:
        articles = fetch_feed(feed_url, lang_code="it", cache_data=cache_data)
        total_articles += articles

    # Save cache
    save_cache(cache_data)

    # Summary
    print("\n" + "="*60)
    print("EXECUTION SUMMARY")
    print("="*60)
    print(f"Total articles created: {total_articles}")
    print(f"Total articles in cache: {len(cache_data['processed_urls'])}")
    print(f"End time: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
    print("="*60 + "\n")

    return 0 if total_articles > 0 else 1

if __name__ == "__main__":
    sys.exit(main())
