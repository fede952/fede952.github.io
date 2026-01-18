#!/usr/bin/env python3
"""
Script per replicare massivamente i contenuti inglesi esistenti
nelle 10 lingue aggiuntive per le sezioni tools, projects, writeups e games.
"""

import os
import re
from pathlib import Path
from typing import Tuple, Optional

# Lingue target (escluso en e it che esistono già)
TARGET_LANGUAGES = ['es', 'zh-cn', 'hi', 'ar', 'pt', 'fr', 'de', 'ja', 'ru', 'ko']

# Sezioni target
TARGET_SECTIONS = ['tools', 'projects', 'writeups', 'games']

# Dizionario delle note tecniche localizzate
TECHNICAL_NOTES = {
    'es': '_Nota: Para preservar la precisión técnica, este contenido se muestra en su idioma original (Inglés)._\n\n---\n',
    'zh-cn': '_注意：为了保持技术准确性，此内容显示为原始语言（英语）。_\n\n---\n',
    'hi': '_नोट: तकनीकी सटीकता बनाए रखने के लिए, यह सामग्री मूल भाषा (अंग्रेजी) में दिखाई गई है।_\n\n---\n',
    'ar': '_ملاحظة: للحفاظ على الدقة التقنية، يتم عرض هذا المحتوى بلغته الأصلية (الإنجليزية)._\n\n---\n',
    'pt': '_Nota: Para preservar a precisão técnica, este conteúdo é exibido em seu idioma original (Inglês)._\n\n---\n',
    'fr': '_Note: Pour préserver la précision technique, ce contenu est affiché dans sa langue d\'origine (Anglais)._\n\n---\n',
    'de': '_Hinweis: Um die technische Genauigkeit zu wahren, wird dieser Inhalt in seiner Originalsprache (Englisch) angezeigt._\n\n---\n',
    'ja': '_注意：技術的な正確性を保つため、このコンテンツは元の言語（英語）で表示されます。_\n\n---\n',
    'ru': '_Примечание: Для сохранения технической точности этот контент отображается на языке оригинала (английском)._\n\n---\n',
    'ko': '_참고: 기술적 정확성을 유지하기 위해 이 콘텐츠는 원래 언어(영어)로 표시됩니다._\n\n---\n'
}

def extract_frontmatter_and_body(content: str) -> Tuple[Optional[str], Optional[str]]:
    """
    Estrae il frontmatter YAML e il body da un file markdown.

    Returns:
        (frontmatter, body) o (None, None) se non trova il frontmatter
    """
    # Pattern per frontmatter YAML delimitato da ---
    match = re.match(r'^---\s*\n(.*?)\n---\s*\n(.*)$', content, re.DOTALL)
    if match:
        return match.group(1).strip(), match.group(2).strip()
    return None, None

def find_source_files(section_path: Path) -> list:
    """
    Trova tutti i file sorgente in inglese in una sezione.
    Cerca file .en.md o .md (senza suffisso lingua).
    Esclude _index.*.md
    """
    source_files = []

    # Cerca file .en.md
    for file in section_path.glob('**/*.en.md'):
        if not file.name.startswith('_index'):
            source_files.append(file)

    # Cerca file .md senza suffisso lingua (potrebbe essere inglese di default)
    for file in section_path.glob('**/*.md'):
        if not file.name.startswith('_index'):
            # Verifica che non abbia già un suffisso lingua
            stem = file.stem
            # Se non finisce con .XX (codice lingua), è probabilmente un file base
            if not any(stem.endswith(f'.{lang}') for lang in TARGET_LANGUAGES + ['en', 'it']):
                # Ma non aggiungerlo se esiste già la versione .en.md
                en_version = file.parent / f"{stem}.en.md"
                if not en_version.exists():
                    source_files.append(file)

    return source_files

def create_localized_content(frontmatter: str, body: str, lang: str) -> str:
    """
    Crea il contenuto localizzato aggiungendo la nota tecnica.
    """
    technical_note = TECHNICAL_NOTES[lang]

    # Ricostruisci il file
    new_content = f"---\n{frontmatter}\n---\n\n{technical_note}\n{body}\n"
    return new_content

def get_target_filename(source_file: Path, lang: str) -> Path:
    """
    Genera il nome del file target per una lingua specifica.

    Esempi:
    - shocker-htb.md -> shocker-htb.es.md
    - password-generator/index.en.md -> password-generator/index.es.md
    """
    stem = source_file.stem

    # Se il file è .en.md, rimuovi .en
    if stem.endswith('.en'):
        stem = stem[:-3]

    # Costruisci il nuovo nome
    new_name = f"{stem}.{lang}.md"
    return source_file.parent / new_name

def replicate_file(source_file: Path, lang: str, dry_run: bool = False) -> bool:
    """
    Replica un singolo file in una lingua target.

    Returns:
        True se il file è stato creato, False altrimenti
    """
    target_file = get_target_filename(source_file, lang)

    # Salta se esiste già
    if target_file.exists():
        return False

    # Leggi il file sorgente
    try:
        with open(source_file, 'r', encoding='utf-8') as f:
            content = f.read()
    except Exception as e:
        print(f"  [ERROR] Cannot read {source_file}: {e}")
        return False

    # Estrai frontmatter e body
    frontmatter, body = extract_frontmatter_and_body(content)

    if not frontmatter or body is None:
        print(f"  [WARN] No frontmatter in {source_file.name}, skipping")
        return False

    # Crea contenuto localizzato
    localized_content = create_localized_content(frontmatter, body, lang)

    if dry_run:
        print(f"  [DRY-RUN] Would create: {target_file.relative_to(source_file.parents[2])}")
        return True

    # Scrivi il file
    try:
        with open(target_file, 'w', encoding='utf-8') as f:
            f.write(localized_content)
        return True
    except Exception as e:
        print(f"  [ERROR] Cannot write {target_file}: {e}")
        return False

def main():
    """Main function per replicare i contenuti."""
    base_path = Path(__file__).parent.parent / 'content'

    stats = {section: 0 for section in TARGET_SECTIONS}
    total_files = 0

    print("\n" + "="*60)
    print("CONTENT REPLICATION - MASSIVE DEPLOYMENT")
    print("="*60 + "\n")

    for idx, section in enumerate(TARGET_SECTIONS, start=1):
        section_path = base_path / section

        print(f"[{idx}/{len(TARGET_SECTIONS)}] Processing section: {section.upper()}")

        if not section_path.exists():
            print(f"  [WARN] Section directory not found: {section_path}")
            print()
            continue

        # Trova tutti i file sorgente in inglese
        source_files = find_source_files(section_path)

        if not source_files:
            print(f"  [INFO] No source files found in {section}")
            print()
            continue

        print(f"  [INFO] Found {len(source_files)} source file(s)")

        # Per ogni file sorgente
        for source_file in source_files:
            files_created = 0

            # Replica in tutte le lingue target
            for lang in TARGET_LANGUAGES:
                if replicate_file(source_file, lang):
                    files_created += 1
                    stats[section] += 1
                    total_files += 1

            if files_created > 0:
                relative_path = source_file.relative_to(base_path)
                print(f"  [OK] {relative_path} -> {files_created} localized versions")

        print()

    # Summary
    print("="*60)
    print("REPLICATION COMPLETED")
    print("="*60)
    print("\n[STATISTICS]")
    for section in TARGET_SECTIONS:
        if stats[section] > 0:
            print(f"  • {section.capitalize()}: {stats[section]} files created")
    print(f"\n[TOTAL] {total_files} files replicated across {len(TARGET_LANGUAGES)} languages")
    print("\n[LANGUAGES] " + ", ".join(TARGET_LANGUAGES))
    print("="*60 + "\n")

    if total_files == 0:
        print("[INFO] No new files created. All content might already be replicated.")
        print("[TIP] Check if source files exist with .en.md or .md extension.\n")

if __name__ == '__main__':
    main()
