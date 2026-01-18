#!/usr/bin/env python3
"""
Create multilingual _index.[lang].md files for password-generator tool
"""

import os
import sys
from pathlib import Path

# Fix Windows console encoding
if sys.platform == 'win32':
    sys.stdout.reconfigure(encoding='utf-8')
    sys.stderr.reconfigure(encoding='utf-8')

BASE_DIR = Path(__file__).parent.parent
TOOL_DIR = BASE_DIR / "content" / "tools" / "password-generator"

# Language configurations
LANGUAGES = {
    'es': {
        'title': 'Generador de Contraseñas Seguras',
        'description': 'Genera contraseñas crip tográficamente seguras con opciones personalizables',
        'link_text': '👉 Ver herramienta en inglés'
    },
    'zh-cn': {
        'title': '安全密码生成器',
        'description': '生成具有可自定义选项的加密安全密码',
        'link_text': '👉 查看英文工具'
    },
    'hi': {
        'title': 'सुरक्षित पासवर्ड जनरेटर',
        'description': 'अनुकूलन योग्य विकल्पों के साथ क्रिप्टोग्राफ़िक रूप से सुरक्षित पासवर्ड उत्पन्न करें',
        'link_text': '👉 अंग्रेजी में टूल देखें'
    },
    'ar': {
        'title': 'مولد كلمات مرور آمنة',
        'description': 'إنشاء كلمات مرور آمنة مشفرة مع خيارات قابلة للتخصيص',
        'link_text': '👉 عرض الأداة بالإنجليزية'
    },
    'pt': {
        'title': 'Gerador de Senhas Seguras',
        'description': 'Gere senhas criptograficamente seguras com opções personalizáveis',
        'link_text': '👉 Ver ferramenta em inglês'
    },
    'fr': {
        'title': 'Générateur de Mots de Passe Sécurisés',
        'description': 'Générez des mots de passe cryptographiquement sécurisés avec des options personnalisables',
        'link_text': '👉 Voir l\'outil en anglais'
    },
    'de': {
        'title': 'Sicherer Passwort-Generator',
        'description': 'Generieren Sie kryptographisch sichere Passwörter mit anpassbaren Optionen',
        'link_text': '👉 Tool auf Englisch ansehen'
    },
    'ja': {
        'title': 'セキュアパスワードジェネレーター',
        'description': 'カスタマイズ可能なオプションで暗号的に安全なパスワードを生成',
        'link_text': '👉 英語でツールを見る'
    },
    'ru': {
        'title': 'Генератор Безопасных Паролей',
        'description': 'Создавайте криптографически безопасные пароли с настраиваемыми параметрами',
        'link_text': '👉 Посмотреть инструмент на английском'
    },
    'ko': {
        'title': '안전한 비밀번호 생성기',
        'description': '사용자 정의 가능한 옵션으로 암호화 보안 비밀번호 생성',
        'link_text': '👉 영어로 도구 보기'
    }
}

def create_index_file(lang, lang_data):
    """Create _index.[lang].md file"""

    filename = f"_index.{lang}.md"
    filepath = TOOL_DIR / filename

    if filepath.exists():
        print(f"  [SKIP] {filename} already exists")
        return False

    content = f"""---
title: "{lang_data['title']}"
description: "{lang_data['description']}"
draft: false
---

⚠️ **Tool Language Notice:**
This interactive tool is currently available in **English** only to ensure technical accuracy and functionality.

[**{lang_data['link_text']}**](/en/tools/password-generator/)

---

**Features:**
- Cryptographically secure password generation
- Customizable length (8-128 characters)
- Multiple character types (uppercase, lowercase, numbers, symbols)
- Password strength indicator
- One-click copy to clipboard
- All operations run locally in your browser
"""

    with open(filepath, 'w', encoding='utf-8') as f:
        f.write(content)

    print(f"  [OK] Created: {filename}")
    return True

def main():
    print("="*60)
    print("CREATE PASSWORD GENERATOR MULTILINGUAL PAGES")
    print("="*60)
    print(f"Tool directory: {TOOL_DIR}")
    print(f"Languages: {len(LANGUAGES)}")
    print("="*60)

    TOOL_DIR.mkdir(parents=True, exist_ok=True)

    total_created = 0

    for lang, lang_data in LANGUAGES.items():
        print(f"\nProcessing: {lang}")
        if create_index_file(lang, lang_data):
            total_created += 1

    print("\n" + "="*60)
    print(f"SUMMARY: Created {total_created} multilingual index files")
    print("="*60)

if __name__ == "__main__":
    main()
