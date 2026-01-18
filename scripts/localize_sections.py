#!/usr/bin/env python3
"""
Script per localizzare le sezioni del sito rimuovendo il Global Content Notice
e creando contenuto nativo per ogni lingua.
"""

import os
from pathlib import Path

# Dizionario di traduzioni per le 10 lingue target
TRANSLATIONS = {
    'es': {
        'writeups': {
            'title': 'CTF Writeups',
            'description': 'Soluciones detalladas de desafíos CTF y análisis de seguridad',
            'intro': 'Explora nuestra colección de writeups de CTF y análisis técnicos de seguridad.'
        },
        'projects': {
            'title': 'Proyectos',
            'description': 'Proyectos de código abierto, herramientas y contribuciones técnicas',
            'intro': 'Descubre mis proyectos de código abierto y herramientas de ciberseguridad.'
        },
        'games': {
            'title': 'Juegos',
            'description': 'Juegos interactivos y herramientas recreativas',
            'intro': 'Explora nuestra colección de juegos interactivos.'
        },
        'tools': {
            'title': 'Herramientas',
            'description': 'Herramientas útiles y utilidades online para desarrolladores',
            'intro': 'Accede a herramientas profesionales y utilidades de desarrollo.'
        }
    },
    'zh-cn': {
        'writeups': {
            'title': 'CTF题解',
            'description': 'CTF挑战详细解答和安全分析',
            'intro': '探索我们的CTF题解和技术安全分析。'
        },
        'projects': {
            'title': '项目',
            'description': '开源项目、工具和技术贡献',
            'intro': '发现我的开源项目和网络安全工具。'
        },
        'games': {
            'title': '游戏',
            'description': '互动游戏和娱乐工具',
            'intro': '探索我们的互动游戏合集。'
        },
        'tools': {
            'title': '工具',
            'description': '面向开发者的实用工具和在线实用程序',
            'intro': '访问专业工具和开发实用程序。'
        }
    },
    'hi': {
        'writeups': {
            'title': 'CTF राइटअप',
            'description': 'CTF चुनौतियों के विस्तृत समाधान और सुरक्षा विश्लेषण',
            'intro': 'हमारे CTF राइटअप और तकनीकी सुरक्षा विश्लेषण का अन्वेषण करें।'
        },
        'projects': {
            'title': 'परियोजनाएं',
            'description': 'ओपन सोर्स परियोजनाएं, उपकरण और तकनीकी योगदान',
            'intro': 'मेरी ओपन सोर्स परियोजनाओं और साइबर सुरक्षा उपकरणों की खोज करें।'
        },
        'games': {
            'title': 'खेल',
            'description': 'इंटरैक्टिव गेम्स और मनोरंजन उपकरण',
            'intro': 'हमारे इंटरैक्टिव गेम्स का संग्रह देखें।'
        },
        'tools': {
            'title': 'उपकरण',
            'description': 'डेवलपर्स के लिए उपयोगी उपकरण और ऑनलाइन यूटिलिटीज',
            'intro': 'पेशेवर उपकरण और विकास यूटिलिटीज तक पहुंचें।'
        }
    },
    'ar': {
        'writeups': {
            'title': 'CTF حلول',
            'description': 'حلول مفصلة لتحديات CTF وتحليل الأمن',
            'intro': 'استكشف مجموعتنا من حلول CTF والتحليلات الأمنية التقنية.'
        },
        'projects': {
            'title': 'المشاريع',
            'description': 'مشاريع مفتوحة المصدر، أدوات ومساهمات تقنية',
            'intro': 'اكتشف مشاريعي مفتوحة المصدر وأدوات الأمن السيبراني.'
        },
        'games': {
            'title': 'الألعاب',
            'description': 'ألعاب تفاعلية وأدوات ترفيهية',
            'intro': 'استكشف مجموعتنا من الألعاب التفاعلية.'
        },
        'tools': {
            'title': 'الأدوات',
            'description': 'أدوات مفيدة وبرامج مساعدة عبر الإنترنت للمطورين',
            'intro': 'الوصول إلى الأدوات المهنية وبرامج التطوير المساعدة.'
        }
    },
    'pt': {
        'writeups': {
            'title': 'CTF Writeups',
            'description': 'Soluções detalhadas de desafios CTF e análises de segurança',
            'intro': 'Explore nossa coleção de writeups CTF e análises técnicas de segurança.'
        },
        'projects': {
            'title': 'Projetos',
            'description': 'Projetos open source, ferramentas e contribuições técnicas',
            'intro': 'Descubra meus projetos open source e ferramentas de cibersegurança.'
        },
        'games': {
            'title': 'Jogos',
            'description': 'Jogos interativos e ferramentas recreativas',
            'intro': 'Explore nossa coleção de jogos interativos.'
        },
        'tools': {
            'title': 'Ferramentas',
            'description': 'Ferramentas úteis e utilitários online para desenvolvedores',
            'intro': 'Acesse ferramentas profissionais e utilitários de desenvolvimento.'
        }
    },
    'fr': {
        'writeups': {
            'title': 'CTF Writeups',
            'description': 'Solutions détaillées des défis CTF et analyses de sécurité',
            'intro': 'Explorez notre collection de writeups CTF et analyses techniques de sécurité.'
        },
        'projects': {
            'title': 'Projets',
            'description': 'Projets open source, outils et contributions techniques',
            'intro': 'Découvrez mes projets open source et outils de cybersécurité.'
        },
        'games': {
            'title': 'Jeux',
            'description': 'Jeux interactifs et outils récréatifs',
            'intro': 'Explorez notre collection de jeux interactifs.'
        },
        'tools': {
            'title': 'Outils',
            'description': 'Outils utiles et utilitaires en ligne pour développeurs',
            'intro': 'Accédez aux outils professionnels et utilitaires de développement.'
        }
    },
    'de': {
        'writeups': {
            'title': 'CTF Writeups',
            'description': 'Detaillierte Lösungen für CTF-Herausforderungen und Sicherheitsanalysen',
            'intro': 'Erkunden Sie unsere Sammlung von CTF-Writeups und technischen Sicherheitsanalysen.'
        },
        'projects': {
            'title': 'Projekte',
            'description': 'Open-Source-Projekte, Tools und technische Beiträge',
            'intro': 'Entdecken Sie meine Open-Source-Projekte und Cybersecurity-Tools.'
        },
        'games': {
            'title': 'Spiele',
            'description': 'Interaktive Spiele und Unterhaltungstools',
            'intro': 'Erkunden Sie unsere Sammlung interaktiver Spiele.'
        },
        'tools': {
            'title': 'Werkzeuge',
            'description': 'Nützliche Tools und Online-Dienstprogramme für Entwickler',
            'intro': 'Zugriff auf professionelle Tools und Entwicklungsdienstprogramme.'
        }
    },
    'ja': {
        'writeups': {
            'title': 'CTF解説',
            'description': 'CTFチャレンジの詳細な解説とセキュリティ分析',
            'intro': '当サイトのCTF解説と技術的なセキュリティ分析をご覧ください。'
        },
        'projects': {
            'title': 'プロジェクト',
            'description': 'オープンソースプロジェクト、ツール、技術貢献',
            'intro': '私のオープンソースプロジェクトとサイバーセキュリティツールをご覧ください。'
        },
        'games': {
            'title': 'ゲーム',
            'description': 'インタラクティブゲームとエンターテインメントツール',
            'intro': 'インタラクティブゲームのコレクションをご覧ください。'
        },
        'tools': {
            'title': 'ツール',
            'description': '開発者向けの便利なツールとオンラインユーティリティ',
            'intro': 'プロフェッショナルツールと開発ユーティリティにアクセスできます。'
        }
    },
    'ru': {
        'writeups': {
            'title': 'CTF Решения',
            'description': 'Подробные решения CTF-задач и анализ безопасности',
            'intro': 'Изучите нашу коллекцию CTF решений и технических анализов безопасности.'
        },
        'projects': {
            'title': 'Проекты',
            'description': 'Проекты с открытым исходным кодом, инструменты и технические вклады',
            'intro': 'Откройте для себя мои проекты с открытым исходным кодом и инструменты кибербезопасности.'
        },
        'games': {
            'title': 'Игры',
            'description': 'Интерактивные игры и развлекательные инструменты',
            'intro': 'Изучите нашу коллекцию интерактивных игр.'
        },
        'tools': {
            'title': 'Инструменты',
            'description': 'Полезные инструменты и онлайн-утилиты для разработчиков',
            'intro': 'Доступ к профессиональным инструментам и утилитам разработки.'
        }
    },
    'ko': {
        'writeups': {
            'title': 'CTF 풀이',
            'description': 'CTF 챌린지의 상세한 풀이 및 보안 분석',
            'intro': 'CTF 풀이 및 기술 보안 분석 컬렉션을 살펴보세요.'
        },
        'projects': {
            'title': '프로젝트',
            'description': '오픈 소스 프로젝트, 도구 및 기술 기여',
            'intro': '오픈 소스 프로젝트와 사이버 보안 도구를 살펴보세요.'
        },
        'games': {
            'title': '게임',
            'description': '인터랙티브 게임 및 엔터테인먼트 도구',
            'intro': '인터랙티브 게임 컬렉션을 살펴보세요.'
        },
        'tools': {
            'title': '도구',
            'description': '개발자를 위한 유용한 도구 및 온라인 유틸리티',
            'intro': '전문 도구 및 개발 유틸리티에 액세스하세요.'
        }
    }
}

# Lingue target (escluso en e it)
TARGET_LANGUAGES = ['es', 'zh-cn', 'hi', 'ar', 'pt', 'fr', 'de', 'ja', 'ru', 'ko']

# Sezioni target (NON toccare 'news')
TARGET_SECTIONS = ['writeups', 'projects', 'games', 'tools']

def create_localized_content(section, lang):
    """Crea il contenuto localizzato per una sezione e lingua specifica."""
    trans = TRANSLATIONS[lang][section]

    content = f"""---
title: "{trans['title']}"
description: "{trans['description']}"
draft: false
---

{trans['intro']}
"""
    return content

def main():
    """Main function per localizzare le sezioni."""
    base_path = Path(__file__).parent.parent / 'content'

    updated_files = []

    for section in TARGET_SECTIONS:
        for lang in TARGET_LANGUAGES:
            # Percorso del file da sovrascrivere
            file_path = base_path / section / f'_index.{lang}.md'

            # Crea il contenuto localizzato
            new_content = create_localized_content(section, lang)

            # Sovrascrivi il file
            try:
                file_path.parent.mkdir(parents=True, exist_ok=True)
                with open(file_path, 'w', encoding='utf-8') as f:
                    f.write(new_content)
                updated_files.append(str(file_path))
                print(f"[OK] Updated: {file_path.relative_to(base_path)}")
            except Exception as e:
                print(f"[ERROR] Error updating {file_path}: {e}")

    print(f"\n[SUCCESS] Successfully updated {len(updated_files)} files!")
    print(f"[INFO] Sections processed: {', '.join(TARGET_SECTIONS)}")
    print(f"[INFO] Languages processed: {', '.join(TARGET_LANGUAGES)}")
    print("\n[DONE] Content is now fully localized (news section untouched as requested)")

if __name__ == '__main__':
    main()
