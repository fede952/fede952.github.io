#!/usr/bin/env python3
"""
Fix language links in multilingual placeholder _index files with proper localization
Updates links to point to /en/ with correctly translated link text for each language
"""

import os
import sys
from pathlib import Path

# Fix Windows console encoding for Unicode characters
if sys.platform == 'win32':
    sys.stdout.reconfigure(encoding='utf-8')
    sys.stderr.reconfigure(encoding='utf-8')

# Base directory
BASE_DIR = Path(__file__).parent.parent
CONTENT_DIR = BASE_DIR / "content"

# Language configurations with translations
LANGUAGES = {
    'es': {
        'name': 'Español',
        'link_text': '👉 Ver contenido en inglés',
        'sections': {
            'news': {
                'title': 'Noticias Tecnológicas',
                'description': 'Últimas noticias sobre ciberseguridad, desarrollo y tecnología'
            },
            'projects': {
                'title': 'Proyectos',
                'description': 'Proyectos de desarrollo y ciberseguridad'
            },
            'writeups': {
                'title': 'CTF Writeups',
                'description': 'Soluciones detalladas de desafíos CTF'
            },
            'games': {
                'title': 'Juegos',
                'description': 'Juegos interactivos y mini-juegos'
            }
        }
    },
    'zh-cn': {
        'name': '简体中文',
        'link_text': '👉 查看英文内容',
        'sections': {
            'news': {
                'title': '科技新闻',
                'description': '网络安全、开发和技术的最新新闻'
            },
            'projects': {
                'title': '项目',
                'description': '开发和网络安全项目'
            },
            'writeups': {
                'title': 'CTF题解',
                'description': 'CTF挑战的详细解决方案'
            },
            'games': {
                'title': '游戏',
                'description': '交互式游戏和迷你游戏'
            }
        }
    },
    'hi': {
        'name': 'हिन्दी',
        'link_text': '👉 अंग्रेजी में सामग्री देखें',
        'sections': {
            'news': {
                'title': 'टेक न्यूज़',
                'description': 'साइबर सुरक्षा, विकास और प्रौद्योगिकी पर नवीनतम समाचार'
            },
            'projects': {
                'title': 'परियोजनाएं',
                'description': 'विकास और साइबर सुरक्षा परियोजनाएं'
            },
            'writeups': {
                'title': 'CTF राइटअप',
                'description': 'CTF चुनौतियों के विस्तृत समाधान'
            },
            'games': {
                'title': 'खेल',
                'description': 'इंटरैक्टिव गेम और मिनी-गेम'
            }
        }
    },
    'ar': {
        'name': 'العربية',
        'link_text': '👉 عرض المحتوى باللغة الإنجليزية',
        'sections': {
            'news': {
                'title': 'أخبار التقنية',
                'description': 'آخر الأخبار حول الأمن السيبراني والتطوير والتكنولوجيا'
            },
            'projects': {
                'title': 'المشاريع',
                'description': 'مشاريع التطوير والأمن السيبراني'
            },
            'writeups': {
                'title': 'حلول CTF',
                'description': 'حلول مفصلة لتحديات CTF'
            },
            'games': {
                'title': 'الألعاب',
                'description': 'ألعاب تفاعلية وألعاب صغيرة'
            }
        }
    },
    'pt': {
        'name': 'Português',
        'link_text': '👉 Ver conteúdo em inglês',
        'sections': {
            'news': {
                'title': 'Notícias Tecnológicas',
                'description': 'Últimas notícias sobre cibersegurança, desenvolvimento e tecnologia'
            },
            'projects': {
                'title': 'Projetos',
                'description': 'Projetos de desenvolvimento e cibersegurança'
            },
            'writeups': {
                'title': 'CTF Writeups',
                'description': 'Soluções detalhadas de desafios CTF'
            },
            'games': {
                'title': 'Jogos',
                'description': 'Jogos interativos e mini-jogos'
            }
        }
    },
    'fr': {
        'name': 'Français',
        'link_text': '👉 Voir le contenu en anglais',
        'sections': {
            'news': {
                'title': 'Actualités Tech',
                'description': 'Dernières nouvelles sur la cybersécurité, le développement et la technologie'
            },
            'projects': {
                'title': 'Projets',
                'description': 'Projets de développement et de cybersécurité'
            },
            'writeups': {
                'title': 'CTF Writeups',
                'description': 'Solutions détaillées de défis CTF'
            },
            'games': {
                'title': 'Jeux',
                'description': 'Jeux interactifs et mini-jeux'
            }
        }
    },
    'de': {
        'name': 'Deutsch',
        'link_text': '👉 Inhalt auf Englisch ansehen',
        'sections': {
            'news': {
                'title': 'Tech News',
                'description': 'Neueste Nachrichten über Cybersicherheit, Entwicklung und Technologie'
            },
            'projects': {
                'title': 'Projekte',
                'description': 'Entwicklungs- und Cybersicherheitsprojekte'
            },
            'writeups': {
                'title': 'CTF Writeups',
                'description': 'Detaillierte Lösungen für CTF-Herausforderungen'
            },
            'games': {
                'title': 'Spiele',
                'description': 'Interaktive Spiele und Mini-Spiele'
            }
        }
    },
    'ja': {
        'name': '日本語',
        'link_text': '👉 英語のコンテンツを見る',
        'sections': {
            'news': {
                'title': 'テックニュース',
                'description': 'サイバーセキュリティ、開発、テクノロジーに関する最新ニュース'
            },
            'projects': {
                'title': 'プロジェクト',
                'description': '開発およびサイバーセキュリティプロジェクト'
            },
            'writeups': {
                'title': 'CTF解説',
                'description': 'CTFチャレンジの詳細な解決策'
            },
            'games': {
                'title': 'ゲーム',
                'description': 'インタラクティブゲームとミニゲーム'
            }
        }
    },
    'ru': {
        'name': 'Русский',
        'link_text': '👉 Посмотреть контент на английском',
        'sections': {
            'news': {
                'title': 'Новости',
                'description': 'Последние новости о кибербезопасности, разработке и технологиях'
            },
            'projects': {
                'title': 'Проекты',
                'description': 'Проекты по разработке и кибербезопасности'
            },
            'writeups': {
                'title': 'CTF Решения',
                'description': 'Подробные решения CTF-задач'
            },
            'games': {
                'title': 'Игры',
                'description': 'Интерактивные игры и мини-игры'
            }
        }
    },
    'ko': {
        'name': '한국어',
        'link_text': '👉 영어로 콘텐츠 보기',
        'sections': {
            'news': {
                'title': '기술 뉴스',
                'description': '사이버 보안, 개발 및 기술에 관한 최신 뉴스'
            },
            'projects': {
                'title': '프로젝트',
                'description': '개발 및 사이버 보안 프로젝트'
            },
            'writeups': {
                'title': 'CTF 풀이',
                'description': 'CTF 챌린지의 상세한 솔루션'
            },
            'games': {
                'title': '게임',
                'description': '인터랙티브 게임 및 미니 게임'
            }
        }
    },
    'it': {
        'name': 'Italiano',
        'link_text': '👉 Vedi contenuti in inglese',
        'sections': {
            'news': {
                'title': 'Notizie Tech',
                'description': 'Ultime notizie su cybersecurity, sviluppo e tecnologia'
            },
            'projects': {
                'title': 'Progetti',
                'description': 'Progetti di sviluppo e cybersecurity'
            },
            'writeups': {
                'title': 'CTF Writeups',
                'description': 'Soluzioni dettagliate delle sfide CTF'
            },
            'games': {
                'title': 'Giochi',
                'description': 'Giochi interattivi e mini-giochi'
            }
        }
    }
}

SECTIONS = ['news', 'projects', 'writeups', 'games']

def fix_section_index(section, lang, lang_data):
    """Fix _index.[lang].md file with correct /en/ link and localized text"""

    section_dir = CONTENT_DIR / section
    section_dir.mkdir(parents=True, exist_ok=True)

    # Filename
    filename = f"_index.{lang}.md"
    filepath = section_dir / filename

    # Get section data
    section_data = lang_data['sections'].get(section, {})
    title = section_data.get('title', section.title())
    description = section_data.get('description', '')

    # Get localized link text
    link_text = lang_data.get('link_text', '👉 View content in English')

    # Build content with CORRECT /en/ link and LOCALIZED text
    content = f"""---
title: "{title}"
description: "{description}"
draft: false
---

⚠️ **Global Content Notice:**
While our interface is translated, the technical articles in this section are primarily available in **English** to maintain technical accuracy.

[**{link_text}**](/en/{section}/)

---
"""

    # Write file
    with open(filepath, 'w', encoding='utf-8') as f:
        f.write(content)

    print(f"  [OK] Fixed: {filepath.relative_to(BASE_DIR)}")
    return True

def main():
    """Main execution function"""
    print("="*60)
    print("FIX MULTILINGUAL LANGUAGE LINKS - LOCALIZED")
    print("="*60)
    print(f"Base directory: {BASE_DIR}")
    print(f"Content directory: {CONTENT_DIR}")
    print(f"Languages: {len(LANGUAGES)}")
    print(f"Sections: {', '.join(SECTIONS)}")
    print("="*60)
    print("\nFixing links with properly localized text for each language...")

    total_fixed = 0

    for lang, lang_data in LANGUAGES.items():
        print(f"\nProcessing language: {lang_data['name']} ({lang})")
        print(f"  Link text: {lang_data['link_text']}")
        for section in SECTIONS:
            if fix_section_index(section, lang, lang_data):
                total_fixed += 1

    print("\n" + "="*60)
    print(f"SUMMARY: Fixed {total_fixed} index files")
    print("="*60)
    print("\nAll links now have:")
    print("  ✓ Correct absolute path: /en/[section]/")
    print("  ✓ Localized link text for each language")
    print("  ✓ Professional user experience")

if __name__ == "__main__":
    main()
