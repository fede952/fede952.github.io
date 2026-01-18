#!/usr/bin/env python3
"""
Generate multilingual _index.[lang].md files for Hugo sections
Creates index files for all non-English languages to prevent 404s
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
        'news': {
            'title': 'Noticias Tecnológicas',
            'description': 'Últimas noticias sobre ciberseguridad, desarrollo y tecnología',
            'notice': '⚠️ **Aviso de Contenido Global:**\nAunque nuestra interfaz está traducida, los artículos técnicos en esta sección están disponibles principalmente en **Inglés** para mantener la precisión técnica.\n\n[Ver contenido en inglés](/news/)'
        },
        'projects': {
            'title': 'Proyectos',
            'description': 'Proyectos de desarrollo y ciberseguridad de Federico Sella',
            'notice': '⚠️ **Aviso de Contenido Global:**\nAunque nuestra interfaz está traducida, la documentación técnica de los proyectos está disponible principalmente en **Inglés** para mantener la precisión técnica.\n\n[Ver contenido en inglés](/projects/)'
        },
        'writeups': {
            'title': 'CTF Writeups',
            'description': 'Soluciones detalladas de desafíos CTF y ejercicios de hacking',
            'notice': '⚠️ **Aviso de Contenido Global:**\nAunque nuestra interfaz está traducida, los writeups técnicos están disponibles principalmente en **Inglés** para mantener la precisión técnica.\n\n[Ver contenido en inglés](/writeups/)'
        },
        'games': {
            'title': 'Juegos',
            'description': 'Juegos interactivos y mini-juegos desarrollados por Federico Sella',
            'notice': '⚠️ **Aviso de Contenido Global:**\nAunque nuestra interfaz está traducida, el contenido de los juegos está disponible principalmente en **Inglés**.\n\n[Ver contenido en inglés](/games/)'
        },
        'about': {
            'title': 'Sobre Mí',
            'description': 'Conoce a Federico Sella - Desarrollador de Seguridad y especialista en Red Team',
            'notice': ''
        }
    },
    'zh-cn': {
        'name': '简体中文',
        'news': {
            'title': '科技新闻',
            'description': '网络安全、开发和技术的最新新闻',
            'notice': '⚠️ **全球内容通知：**\n虽然我们的界面已翻译，但本节中的技术文章主要以**英文**提供，以保持技术准确性。\n\n[查看英文内容](/news/)'
        },
        'projects': {
            'title': '项目',
            'description': 'Federico Sella的开发和网络安全项目',
            'notice': '⚠️ **全球内容通知：**\n虽然我们的界面已翻译，但项目技术文档主要以**英文**提供，以保持技术准确性。\n\n[查看英文内容](/projects/)'
        },
        'writeups': {
            'title': 'CTF题解',
            'description': 'CTF挑战和黑客练习的详细解决方案',
            'notice': '⚠️ **全球内容通知：**\n虽然我们的界面已翻译，但技术题解主要以**英文**提供，以保持技术准确性。\n\n[查看英文内容](/writeups/)'
        },
        'games': {
            'title': '游戏',
            'description': 'Federico Sella开发的交互式游戏和迷你游戏',
            'notice': '⚠️ **全球内容通知：**\n虽然我们的界面已翻译，但游戏内容主要以**英文**提供。\n\n[查看英文内容](/games/)'
        },
        'about': {
            'title': '关于我',
            'description': '认识Federico Sella - 安全开发者和红队专家',
            'notice': ''
        }
    },
    'hi': {
        'name': 'हिन्दी',
        'news': {
            'title': 'टेक न्यूज़',
            'description': 'साइबर सुरक्षा, विकास और प्रौद्योगिकी पर नवीनतम समाचार',
            'notice': '⚠️ **वैश्विक सामग्री सूचना:**\nजबकि हमारा इंटरफ़ेस अनुवादित है, इस अनुभाग में तकनीकी लेख मुख्य रूप से तकनीकी सटीकता बनाए रखने के लिए **अंग्रेजी** में उपलब्ध हैं।\n\n[अंग्रेजी सामग्री देखें](/news/)'
        },
        'projects': {
            'title': 'परियोजनाएं',
            'description': 'Federico Sella की विकास और साइबर सुरक्षा परियोजनाएं',
            'notice': '⚠️ **वैश्विक सामग्री सूचना:**\nजबकि हमारा इंटरफ़ेस अनुवादित है, परियोजना तकनीकी दस्तावेज़ीकरण मुख्य रूप से **अंग्रेजी** में उपलब्ध है।\n\n[अंग्रेजी सामग्री देखें](/projects/)'
        },
        'writeups': {
            'title': 'CTF राइटअप',
            'description': 'CTF चुनौतियों और हैकिंग अभ्यासों के विस्तृत समाधान',
            'notice': '⚠️ **वैश्विक सामग्री सूचना:**\nजबकि हमारा इंटरफ़ेस अनुवादित है, तकनीकी राइटअप मुख्य रूप से **अंग्रेजी** में उपलब्ध हैं।\n\n[अंग्रेजी सामग्री देखें](/writeups/)'
        },
        'games': {
            'title': 'खेल',
            'description': 'Federico Sella द्वारा विकसित इंटरैक्टिव गेम और मिनी-गेम',
            'notice': '⚠️ **वैश्विक सामग्री सूचना:**\nजबकि हमारा इंटरफ़ेस अनुवादित है, गेम सामग्री मुख्य रूप से **अंग्रेजी** में उपलब्ध है।\n\n[अंग्रेजी सामग्री देखें](/games/)'
        },
        'about': {
            'title': 'मेरे बारे में',
            'description': 'Federico Sella को जानें - सुरक्षा डेवलपर और रेड टीम विशेषज्ञ',
            'notice': ''
        }
    },
    'ar': {
        'name': 'العربية',
        'news': {
            'title': 'أخبار التقنية',
            'description': 'آخر الأخبار حول الأمن السيبراني والتطوير والتكنولوجيا',
            'notice': '⚠️ **إشعار المحتوى العالمي:**\nبينما تمت ترجمة واجهتنا، المقالات التقنية في هذا القسم متاحة بشكل أساسي **بالإنجليزية** للحفاظ على الدقة التقنية.\n\n[عرض المحتوى بالإنجليزية](/news/)'
        },
        'projects': {
            'title': 'المشاريع',
            'description': 'مشاريع التطوير والأمن السيبراني لـ Federico Sella',
            'notice': '⚠️ **إشعار المحتوى العالمي:**\nبينما تمت ترجمة واجهتنا، الوثائق التقنية للمشاريع متاحة بشكل أساسي **بالإنجليزية** للحفاظ على الدقة التقنية.\n\n[عرض المحتوى بالإنجليزية](/projects/)'
        },
        'writeups': {
            'title': 'حلول CTF',
            'description': 'حلول مفصلة لتحديات CTF وتمارين الاختراق',
            'notice': '⚠️ **إشعار المحتوى العالمي:**\nبينما تمت ترجمة واجهتنا، الحلول التقنية متاحة بشكل أساسي **بالإنجليزية** للحفاظ على الدقة التقنية.\n\n[عرض المحتوى بالإنجليزية](/writeups/)'
        },
        'games': {
            'title': 'الألعاب',
            'description': 'ألعاب تفاعلية وألعاب صغيرة طورها Federico Sella',
            'notice': '⚠️ **إشعار المحتوى العالمي:**\nبينما تمت ترجمة واجهتنا، محتوى الألعاب متاح بشكل أساسي **بالإنجليزية**.\n\n[عرض المحتوى بالإنجليزية](/games/)'
        },
        'about': {
            'title': 'عني',
            'description': 'تعرف على Federico Sella - مطور أمن وخبير الفريق الأحمر',
            'notice': ''
        }
    },
    'pt': {
        'name': 'Português',
        'news': {
            'title': 'Notícias Tecnológicas',
            'description': 'Últimas notícias sobre cibersegurança, desenvolvimento e tecnologia',
            'notice': '⚠️ **Aviso de Conteúdo Global:**\nEmbora nossa interface esteja traduzida, os artigos técnicos desta seção estão disponíveis principalmente em **Inglês** para manter a precisão técnica.\n\n[Ver conteúdo em inglês](/news/)'
        },
        'projects': {
            'title': 'Projetos',
            'description': 'Projetos de desenvolvimento e cibersegurança de Federico Sella',
            'notice': '⚠️ **Aviso de Conteúdo Global:**\nEmbora nossa interface esteja traduzida, a documentação técnica dos projetos está disponível principalmente em **Inglês** para manter a precisão técnica.\n\n[Ver conteúdo em inglês](/projects/)'
        },
        'writeups': {
            'title': 'CTF Writeups',
            'description': 'Soluções detalhadas de desafios CTF e exercícios de hacking',
            'notice': '⚠️ **Aviso de Conteúdo Global:**\nEmbora nossa interface esteja traduzida, os writeups técnicos estão disponíveis principalmente em **Inglês** para manter a precisão técnica.\n\n[Ver conteúdo em inglês](/writeups/)'
        },
        'games': {
            'title': 'Jogos',
            'description': 'Jogos interativos e mini-jogos desenvolvidos por Federico Sella',
            'notice': '⚠️ **Aviso de Conteúdo Global:**\nEmbora nossa interface esteja traduzida, o conteúdo dos jogos está disponível principalmente em **Inglês**.\n\n[Ver conteúdo em inglês](/games/)'
        },
        'about': {
            'title': 'Sobre Mim',
            'description': 'Conheça Federico Sella - Desenvolvedor de Segurança e especialista em Red Team',
            'notice': ''
        }
    },
    'fr': {
        'name': 'Français',
        'news': {
            'title': 'Actualités Tech',
            'description': 'Dernières nouvelles sur la cybersécurité, le développement et la technologie',
            'notice': '⚠️ **Avis de Contenu Global :**\nBien que notre interface soit traduite, les articles techniques de cette section sont principalement disponibles en **Anglais** pour maintenir la précision technique.\n\n[Voir le contenu en anglais](/news/)'
        },
        'projects': {
            'title': 'Projets',
            'description': 'Projets de développement et de cybersécurité de Federico Sella',
            'notice': '⚠️ **Avis de Contenu Global :**\nBien que notre interface soit traduite, la documentation technique des projets est principalement disponible en **Anglais** pour maintenir la précision technique.\n\n[Voir le contenu en anglais](/projects/)'
        },
        'writeups': {
            'title': 'CTF Writeups',
            'description': 'Solutions détaillées de défis CTF et exercices de hacking',
            'notice': '⚠️ **Avis de Contenu Global :**\nBien que notre interface soit traduite, les writeups techniques sont principalement disponibles en **Anglais** pour maintenir la précision technique.\n\n[Voir le contenu en anglais](/writeups/)'
        },
        'games': {
            'title': 'Jeux',
            'description': 'Jeux interactifs et mini-jeux développés par Federico Sella',
            'notice': '⚠️ **Avis de Contenu Global :**\nBien que notre interface soit traduite, le contenu des jeux est principalement disponible en **Anglais**.\n\n[Voir le contenu en anglais](/games/)'
        },
        'about': {
            'title': 'À Propos',
            'description': 'Découvrez Federico Sella - Développeur Sécurité et spécialiste Red Team',
            'notice': ''
        }
    },
    'de': {
        'name': 'Deutsch',
        'news': {
            'title': 'Tech News',
            'description': 'Neueste Nachrichten über Cybersicherheit, Entwicklung und Technologie',
            'notice': '⚠️ **Globaler Inhaltshinweis:**\nObwohl unsere Benutzeroberfläche übersetzt ist, sind die technischen Artikel in diesem Bereich hauptsächlich auf **Englisch** verfügbar, um technische Genauigkeit zu gewährleisten.\n\n[Inhalt auf Englisch ansehen](/news/)'
        },
        'projects': {
            'title': 'Projekte',
            'description': 'Entwicklungs- und Cybersicherheitsprojekte von Federico Sella',
            'notice': '⚠️ **Globaler Inhaltshinweis:**\nObwohl unsere Benutzeroberfläche übersetzt ist, ist die technische Dokumentation der Projekte hauptsächlich auf **Englisch** verfügbar, um technische Genauigkeit zu gewährleisten.\n\n[Inhalt auf Englisch ansehen](/projects/)'
        },
        'writeups': {
            'title': 'CTF Writeups',
            'description': 'Detaillierte Lösungen für CTF-Herausforderungen und Hacking-Übungen',
            'notice': '⚠️ **Globaler Inhaltshinweis:**\nObwohl unsere Benutzeroberfläche übersetzt ist, sind die technischen Writeups hauptsächlich auf **Englisch** verfügbar, um technische Genauigkeit zu gewährleisten.\n\n[Inhalt auf Englisch ansehen](/writeups/)'
        },
        'games': {
            'title': 'Spiele',
            'description': 'Interaktive Spiele und Mini-Spiele entwickelt von Federico Sella',
            'notice': '⚠️ **Globaler Inhaltshinweis:**\nObwohl unsere Benutzeroberfläche übersetzt ist, ist der Spielinhalt hauptsächlich auf **Englisch** verfügbar.\n\n[Inhalt auf Englisch ansehen](/games/)'
        },
        'about': {
            'title': 'Über Mich',
            'description': 'Lernen Sie Federico Sella kennen - Sicherheitsentwickler und Red Team Spezialist',
            'notice': ''
        }
    },
    'ja': {
        'name': '日本語',
        'news': {
            'title': 'テックニュース',
            'description': 'サイバーセキュリティ、開発、テクノロジーに関する最新ニュース',
            'notice': '⚠️ **グローバルコンテンツ通知：**\nインターフェースは翻訳されていますが、このセクションの技術記事は技術的な正確性を維持するため、主に**英語**で提供されています。\n\n[英語のコンテンツを見る](/news/)'
        },
        'projects': {
            'title': 'プロジェクト',
            'description': 'Federico Sellaの開発およびサイバーセキュリティプロジェクト',
            'notice': '⚠️ **グローバルコンテンツ通知：**\nインターフェースは翻訳されていますが、プロジェクトの技術文書は技術的な正確性を維持するため、主に**英語**で提供されています。\n\n[英語のコンテンツを見る](/projects/)'
        },
        'writeups': {
            'title': 'CTF解説',
            'description': 'CTFチャレンジとハッキング演習の詳細な解決策',
            'notice': '⚠️ **グローバルコンテンツ通知：**\nインターフェースは翻訳されていますが、技術的な解説は技術的な正確性を維持するため、主に**英語**で提供されています。\n\n[英語のコンテンツを見る](/writeups/)'
        },
        'games': {
            'title': 'ゲーム',
            'description': 'Federico Sellaが開発したインタラクティブゲームとミニゲーム',
            'notice': '⚠️ **グローバルコンテンツ通知：**\nインターフェースは翻訳されていますが、ゲームコンテンツは主に**英語**で提供されています。\n\n[英語のコンテンツを見る](/games/)'
        },
        'about': {
            'title': '私について',
            'description': 'Federico Sellaについて - セキュリティ開発者およびレッドチームスペシャリスト',
            'notice': ''
        }
    },
    'ru': {
        'name': 'Русский',
        'news': {
            'title': 'Новости',
            'description': 'Последние новости о кибербезопасности, разработке и технологиях',
            'notice': '⚠️ **Глобальное уведомление о содержании:**\nХотя наш интерфейс переведен, технические статьи в этом разделе доступны в основном на **английском** языке для поддержания технической точности.\n\n[Просмотреть контент на английском](/news/)'
        },
        'projects': {
            'title': 'Проекты',
            'description': 'Проекты по разработке и кибербезопасности Federico Sella',
            'notice': '⚠️ **Глобальное уведомление о содержании:**\nХотя наш интерфейс переведен, техническая документация проектов доступна в основном на **английском** языке для поддержания технической точности.\n\n[Просмотреть контент на английском](/projects/)'
        },
        'writeups': {
            'title': 'CTF Решения',
            'description': 'Подробные решения CTF-задач и упражнений по хакингу',
            'notice': '⚠️ **Глобальное уведомление о содержании:**\nХотя наш интерфейс переведен, технические решения доступны в основном на **английском** языке для поддержания технической точности.\n\n[Просмотреть контент на английском](/writeups/)'
        },
        'games': {
            'title': 'Игры',
            'description': 'Интерактивные игры и мини-игры, разработанные Federico Sella',
            'notice': '⚠️ **Глобальное уведомление о содержании:**\nХотя наш интерфейс переведен, содержание игр доступно в основном на **английском** языке.\n\n[Просмотреть контент на английском](/games/)'
        },
        'about': {
            'title': 'Обо Мне',
            'description': 'Познакомьтесь с Federico Sella - разработчик безопасности и специалист Red Team',
            'notice': ''
        }
    },
    'ko': {
        'name': '한국어',
        'news': {
            'title': '기술 뉴스',
            'description': '사이버 보안, 개발 및 기술에 관한 최신 뉴스',
            'notice': '⚠️ **글로벌 콘텐츠 공지:**\n인터페이스가 번역되어 있지만, 이 섹션의 기술 기사는 기술적 정확성을 유지하기 위해 주로 **영어**로 제공됩니다.\n\n[영어 콘텐츠 보기](/news/)'
        },
        'projects': {
            'title': '프로젝트',
            'description': 'Federico Sella의 개발 및 사이버 보안 프로젝트',
            'notice': '⚠️ **글로벌 콘텐츠 공지:**\n인터페이스가 번역되어 있지만, 프로젝트 기술 문서는 기술적 정확성을 유지하기 위해 주로 **영어**로 제공됩니다.\n\n[영어 콘텐츠 보기](/projects/)'
        },
        'writeups': {
            'title': 'CTF 풀이',
            'description': 'CTF 챌린지 및 해킹 연습의 상세한 솔루션',
            'notice': '⚠️ **글로벌 콘텐츠 공지:**\n인터페이스가 번역되어 있지만, 기술 풀이는 기술적 정확성을 유지하기 위해 주로 **영어**로 제공됩니다.\n\n[영어 콘텐츠 보기](/writeups/)'
        },
        'games': {
            'title': '게임',
            'description': 'Federico Sella가 개발한 인터랙티브 게임 및 미니 게임',
            'notice': '⚠️ **글로벌 콘텐츠 공지:**\n인터페이스가 번역되어 있지만, 게임 콘텐츠는 주로 **영어**로 제공됩니다.\n\n[영어 콘텐츠 보기](/games/)'
        },
        'about': {
            'title': '소개',
            'description': 'Federico Sella 소개 - 보안 개발자 및 레드팀 전문가',
            'notice': ''
        }
    }
}

SECTIONS = ['news', 'projects', 'writeups', 'games', 'about']

def generate_index_file(section, lang, lang_data):
    """Generate _index.[lang].md file for a given section and language"""

    section_dir = CONTENT_DIR / section
    section_dir.mkdir(parents=True, exist_ok=True)

    # File path
    filename = f"_index.{lang}.md"
    filepath = section_dir / filename

    # Skip if file already exists
    if filepath.exists():
        print(f"  [SKIP] {filepath.relative_to(BASE_DIR)} already exists")
        return False

    # Get section data
    section_data = lang_data.get(section, {})
    title = section_data.get('title', section.title())
    description = section_data.get('description', '')
    notice = section_data.get('notice', '')

    # Build content
    content = f"""---
title: "{title}"
description: "{description}"
draft: false
---

{notice}
"""

    # Write file
    with open(filepath, 'w', encoding='utf-8') as f:
        f.write(content)

    print(f"  [OK] Created: {filepath.relative_to(BASE_DIR)}")
    return True

def main():
    """Main execution function"""
    print("="*60)
    print("HUGO MULTILINGUAL INDEX GENERATOR")
    print("="*60)
    print(f"Base directory: {BASE_DIR}")
    print(f"Content directory: {CONTENT_DIR}")
    print(f"Languages: {', '.join(LANGUAGES.keys())}")
    print(f"Sections: {', '.join(SECTIONS)}")
    print("="*60)

    total_created = 0

    for lang, lang_data in LANGUAGES.items():
        print(f"\nProcessing language: {lang_data['name']} ({lang})")
        for section in SECTIONS:
            if generate_index_file(section, lang, lang_data):
                total_created += 1

    print("\n" + "="*60)
    print(f"SUMMARY: Created {total_created} new index files")
    print("="*60)

if __name__ == "__main__":
    main()
