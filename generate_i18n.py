#!/usr/bin/env python3
"""
Generate placeholder i18n localization files
Creates basic i18n_en.yaml and i18n_ru.yaml for each correlation
"""

import json
from pathlib import Path

WINDOWS_RULES_DIR = Path("windows_correlation_rules")

# Localization templates
EN_TEMPLATE = """Description: 'The rule detects {technique_desc} activity based on Windows security events'
EventDescriptions:
    - LocalizationId: 'corrname_{corr_name}'
      EventDescription: 'User {{subject.account.name}} executed {{subject.process.name}} with command {{subject.process.cmdline}} on host {{event_src.hostname}}'
"""

RU_TEMPLATE = """Description: 'Правило обнаруживает активность связанную с {technique_desc} на основе событий безопасности Windows'
EventDescriptions:
    - LocalizationId: 'corrname_{corr_name}'
      EventDescription: 'Пользователь {{subject.account.name}} выполнил процесс {{subject.process.name}} с командой {{subject.process.cmdline}} на узле {{event_src.hostname}}'
"""

# Technique descriptions
TECHNIQUE_DESC = {
    "Inhibit System Recovery": {
        "en": "system recovery inhibition (deletion of backups and shadow copies)",
        "ru": "подавлением восстановления системы (удаление резервных копий и теневых копий)"
    },
    "OS Credential Dumping": {
        "en": "credential dumping from operating system",
        "ru": "извлечением учетных данных из операционной системы"
    },
    "Create Account": {
        "en": "account creation",
        "ru": "созданием учетных записей"
    },
    "Obfuscated Files or Information": {
        "en": "obfuscated commands and encoded data",
        "ru": "обфусцированными командами и закодированными данными"
    },
    "Command and Scripting Interpreter": {
        "en": "suspicious command execution and scripting",
        "ru": "подозрительным выполнением команд и скриптов"
    },
    "Scheduled Task": {
        "en": "scheduled task creation",
        "ru": "созданием запланированных задач"
    },
    "Remote Services": {
        "en": "remote service execution",
        "ru": "удаленным выполнением служб"
    },
    "System Information Discovery": {
        "en": "system information gathering",
        "ru": "сбором информации о системе"
    },
    "Valid Accounts": {
        "en": "authentication using valid accounts",
        "ru": "аутентификацией с использованием действительных учетных записей"
    },
    "Process Injection": {
        "en": "process injection",
        "ru": "внедрением в процессы"
    },
}


def get_technique_description(technique: str, lang: str) -> str:
    """Get localized technique description"""
    for key in TECHNIQUE_DESC:
        if key in technique:
            return TECHNIQUE_DESC[key][lang]
    
    # Default
    if lang == "ru":
        return "подозрительной активностью"
    return "suspicious activity"


def generate_i18n(corr_dir: Path):
    """Generate i18n files for a correlation"""
    i18n_dir = corr_dir / "i18n"
    
    # Skip if already exists
    if i18n_dir.exists():
        print(f"  Skipping (i18n directory exists)")
        return
    
    # Read answers.json to get technique
    answers_file = corr_dir / "answers.json"
    if not answers_file.exists():
        print(f"  No answers.json found")
        return
    
    with open(answers_file, 'r', encoding='utf-8') as f:
        answers = json.load(f)
    
    technique = answers.get("technique", "Unknown")
    
    # Get descriptions
    en_desc = get_technique_description(technique, "en")
    ru_desc = get_technique_description(technique, "ru")
    
    # Create i18n directory
    i18n_dir.mkdir(exist_ok=True)
    
    # Generate English
    en_content = EN_TEMPLATE.format(
        technique_desc=en_desc,
        corr_name=corr_dir.name
    )
    with open(i18n_dir / "i18n_en.yaml", 'w', encoding='utf-8') as f:
        f.write(en_content)
    
    # Generate Russian
    ru_content = RU_TEMPLATE.format(
        technique_desc=ru_desc,
        corr_name=corr_dir.name
    )
    with open(i18n_dir / "i18n_ru.yaml", 'w', encoding='utf-8') as f:
        f.write(ru_content)
    
    print(f"  Created i18n files")


def main():
    print("="*60)
    print("Generating i18n localization files")
    print("="*60)
    
    for corr_dir in sorted(WINDOWS_RULES_DIR.glob("correlation_*")):
        if not corr_dir.is_dir():
            continue
        
        print(f"\nProcessing {corr_dir.name}...")
        try:
            generate_i18n(corr_dir)
        except Exception as e:
            print(f"  Error: {e}")
    
    print("\n" + "="*60)
    print("Complete!")
    print("="*60)


if __name__ == "__main__":
    main()
