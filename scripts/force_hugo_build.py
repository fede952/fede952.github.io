#!/usr/bin/env python3
"""
Force Hugo to build multilingual section pages by creating placeholder content
This ensures all language section pages render correctly even without translated content
"""

import os
import sys
from pathlib import Path
from datetime import datetime

# Fix Windows console encoding for Unicode characters
if sys.platform == 'win32':
    sys.stdout.reconfigure(encoding='utf-8')
    sys.stderr.reconfigure(encoding='utf-8')

# Base directory
BASE_DIR = Path(__file__).parent.parent
CONTENT_DIR = BASE_DIR / "content"

# Language configurations
LANGUAGES = {
    'es': {
        'name': 'Español',
        'welcome': 'Bienvenido',
        'notice': 'Estamos configurando la sección en español. Mientras tanto, consulta nuestro contenido en inglés.'
    },
    'zh-cn': {
        'name': '简体中文',
        'welcome': '欢迎',
        'notice': '我们正在设置中文部分。同时，请查看我们的英文内容。'
    },
    'hi': {
        'name': 'हिन्दी',
        'welcome': 'स्वागत है',
        'notice': 'हम हिंदी अनुभाग की स्थापना कर रहे हैं। इस बीच, हमारी अंग्रेजी सामग्री देखें।'
    },
    'ar': {
        'name': 'العربية',
        'welcome': 'أهلا وسهلا',
        'notice': 'نحن نقوم بإعداد القسم العربي. في هذه الأثناء، تحقق من المحتوى الإنجليزي.'
    },
    'pt': {
        'name': 'Português',
        'welcome': 'Bem-vindo',
        'notice': 'Estamos configurando a seção em português. Enquanto isso, confira nosso conteúdo em inglês.'
    },
    'fr': {
        'name': 'Français',
        'welcome': 'Bienvenue',
        'notice': 'Nous configurons la section française. En attendant, consultez notre contenu en anglais.'
    },
    'de': {
        'name': 'Deutsch',
        'welcome': 'Willkommen',
        'notice': 'Wir richten den deutschen Bereich ein. In der Zwischenzeit können Sie unsere englischen Inhalte ansehen.'
    },
    'ja': {
        'name': '日本語',
        'welcome': 'ようこそ',
        'notice': '日本語セクションを設定しています。その間、英語のコンテンツをご覧ください。'
    },
    'ru': {
        'name': 'Русский',
        'welcome': 'Добро пожаловать',
        'notice': 'Мы настраиваем русский раздел. А пока ознакомьтесь с нашим английским контентом.'
    },
    'ko': {
        'name': '한국어',
        'welcome': '환영합니다',
        'notice': '한국어 섹션을 설정 중입니다. 그동안 영어 콘텐츠를 확인해 주세요.'
    },
    'it': {
        'name': 'Italiano',
        'welcome': 'Benvenuto',
        'notice': 'Stiamo configurando la sezione italiana. Nel frattempo, consulta i nostri contenuti in inglese.'
    }
}

# Critical sections that need placeholder content
SECTIONS = {
    'news': {
        'slug': 'welcome-to-news',
        'title_suffix': 'Tech News'
    },
    'projects': {
        'slug': 'welcome-to-projects',
        'title_suffix': 'Projects'
    },
    'writeups': {
        'slug': 'welcome-to-writeups',
        'title_suffix': 'CTF Writeups'
    },
    'games': {
        'slug': 'welcome-to-games',
        'title_suffix': 'Games'
    }
}

def create_placeholder(section, section_data, lang, lang_data):
    """Create placeholder content file for a section and language"""

    section_dir = CONTENT_DIR / section
    section_dir.mkdir(parents=True, exist_ok=True)

    # Filename with language suffix
    filename = f"{section_data['slug']}.{lang}.md"
    filepath = section_dir / filename

    # Skip if file already exists
    if filepath.exists():
        print(f"  [SKIP] {filepath.relative_to(BASE_DIR)} already exists")
        return False

    # Build content
    welcome = lang_data['welcome']
    lang_name = lang_data['name']
    notice = lang_data['notice']
    title_suffix = section_data['title_suffix']

    # Get current date
    current_date = datetime.now().strftime('%Y-%m-%d')

    content = f"""---
title: "{welcome} / Welcome - {title_suffix}"
date: {current_date}T00:00:00
draft: false
hidemeta: true
showToc: false
description: "Multilingual placeholder content for {section} section"
---

## {welcome} to {title_suffix}

{notice}

**Language:** {lang_name} ({lang})

---

[🔗 View English Content](/{section}/)
"""

    # Write file
    with open(filepath, 'w', encoding='utf-8') as f:
        f.write(content)

    print(f"  [OK] Created: {filepath.relative_to(BASE_DIR)}")
    return True

def main():
    """Main execution function"""
    print("="*60)
    print("HUGO MULTILINGUAL PLACEHOLDER GENERATOR")
    print("="*60)
    print(f"Base directory: {BASE_DIR}")
    print(f"Content directory: {CONTENT_DIR}")
    print(f"Languages: {len(LANGUAGES)}")
    print(f"Sections: {', '.join(SECTIONS.keys())}")
    print("="*60)

    total_created = 0

    for lang, lang_data in LANGUAGES.items():
        print(f"\nProcessing language: {lang_data['name']} ({lang})")
        for section, section_data in SECTIONS.items():
            if create_placeholder(section, section_data, lang, lang_data):
                total_created += 1

    print("\n" + "="*60)
    print(f"SUMMARY: Created {total_created} placeholder files")
    print("="*60)
    print("\nThese placeholder files force Hugo to generate section list")
    print("pages for all languages, preventing 404 errors.")
    print("\nYou can safely delete or update these files later once you")
    print("have real translated content for each section.")

if __name__ == "__main__":
    main()
