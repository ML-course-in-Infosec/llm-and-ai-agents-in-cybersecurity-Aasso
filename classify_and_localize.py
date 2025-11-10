#!/usr/bin/env python3
"""
Task 2 & 3: MITRE ATT&CK Classification and Localization Generation
Uses LLM (Claude/GPT-4) to analyze events and generate answers.json + i18n files
"""

import json
import os
import yaml
from pathlib import Path
from typing import Dict, List, Any, Optional
import anthropic
import openai

# Configuration
WINDOWS_RULES_DIR = Path("windows_correlation_rules")
MACOS_RULES_DIR = Path("macos_correlation_rules")

# API Configuration - Set your API key
# Option 1: Anthropic Claude (recommended)
ANTHROPIC_API_KEY = os.getenv("ANTHROPIC_API_KEY", "")
# Option 2: OpenAI GPT-4
OPENAI_API_KEY = os.getenv("OPENAI_API_KEY", "")

USE_ANTHROPIC = True  # Set to False to use OpenAI instead


def load_example_localizations() -> Dict[str, str]:
    """Load example localization files from macOS rules"""
    examples = {
        "en": [],
        "ru": []
    }
    
    # Load a few examples
    for tactic_dir in (MACOS_RULES_DIR).glob("*"):
        if not tactic_dir.is_dir():
            continue
        for rule_dir in tactic_dir.glob("*"):
            if not rule_dir.is_dir():
                continue
            
            i18n_dir = rule_dir / "i18n"
            if not i18n_dir.exists():
                continue
            
            en_file = i18n_dir / "i18n_en.yaml"
            ru_file = i18n_dir / "i18n_ru.yaml"
            
            if en_file.exists() and ru_file.exists():
                with open(en_file, 'r', encoding='utf-8') as f:
                    examples["en"].append(f.read())
                with open(ru_file, 'r', encoding='utf-8') as f:
                    examples["ru"].append(f.read())
                
                if len(examples["en"]) >= 3:
                    break
        if len(examples["en"]) >= 3:
            break
    
    return examples


def call_llm(prompt: str, system_prompt: str = "") -> str:
    """Call LLM API (Claude or GPT-4)"""
    if USE_ANTHROPIC and ANTHROPIC_API_KEY:
        client = anthropic.Anthropic(api_key=ANTHROPIC_API_KEY)
        message = client.messages.create(
            model="claude-3-5-sonnet-20241022",
            max_tokens=4096,
            system=system_prompt if system_prompt else "You are a cybersecurity expert.",
            messages=[
                {"role": "user", "content": prompt}
            ]
        )
        return message.content[0].text
    
    elif OPENAI_API_KEY:
        client = openai.OpenAI(api_key=OPENAI_API_KEY)
        messages = []
        if system_prompt:
            messages.append({"role": "system", "content": system_prompt})
        messages.append({"role": "user", "content": prompt})
        
        response = client.chat.completions.create(
            model="gpt-4-turbo-preview",
            messages=messages,
            temperature=0.3
        )
        return response.choices[0].message.content
    
    else:
        raise ValueError("No API key configured. Set ANTHROPIC_API_KEY or OPENAI_API_KEY environment variable.")


def classify_mitre_attack(norm_fields_group: List[Dict]) -> Dict[str, str]:
    """
    Classify events and determine MITRE ATT&CK tactic, technique, and importance
    
    Args:
        norm_fields_group: List of normalized event dictionaries for a group (same i index)
    
    Returns:
        Dict with keys: tactic, technique, importance
    """
    # Prepare event summary
    event_summary = []
    for idx, event in enumerate(norm_fields_group):
        summary = f"Event {idx + 1}:\n"
        for key, value in event.items():
            summary += f"  {key}: {value}\n"
        event_summary.append(summary)
    
    events_text = "\n".join(event_summary)
    
    system_prompt = """You are a cybersecurity expert specializing in MITRE ATT&CK framework and SIEM correlation rules.
Your task is to analyze Windows security events and classify them according to MITRE ATT&CK tactics and techniques.

Guidelines:
1. Use exact tactic and technique names from https://attack.mitre.org/
2. If a sub-technique applies, use format: "Main Technique: Sub-Technique"
3. Importance levels: low, medium, high (based on potential impact and severity)
4. Focus on the primary attack behavior demonstrated by the event sequence

Output must be valid JSON only, no additional text."""

    prompt = f"""Analyze the following normalized Windows security events and determine:
1. MITRE ATT&CK Tactic (e.g., "Credential Access", "Defense Evasion")
2. MITRE ATT&CK Technique (e.g., "OS Credential Dumping", "Obfuscated Files or Information")
3. Importance level (low, medium, or high)

Events:
{events_text}

Output format (JSON only):
{{
  "tactic": "Tactic Name",
  "technique": "Technique Name",
  "importance": "high"
}}

If a sub-technique is relevant, use this format:
{{
  "tactic": "Tactic Name",
  "technique": "Main Technique: Sub-Technique Name",
  "importance": "high"
}}

JSON output:"""

    response = call_llm(prompt, system_prompt)
    
    # Extract JSON from response
    try:
        # Try to find JSON in the response
        json_start = response.find("{")
        json_end = response.rfind("}") + 1
        if json_start >= 0 and json_end > json_start:
            json_str = response[json_start:json_end]
            result = json.loads(json_str)
            return result
        else:
            raise ValueError("No JSON found in response")
    except Exception as e:
        print(f"Error parsing LLM response: {e}")
        print(f"Response was: {response}")
        # Return default
        return {
            "tactic": "Unknown",
            "technique": "Unknown",
            "importance": "medium"
        }


def generate_localization(norm_fields_group: List[Dict], mitre_info: Dict, examples: Dict) -> Dict[str, str]:
    """
    Generate i18n_en.yaml and i18n_ru.yaml files
    
    Args:
        norm_fields_group: List of normalized events
        mitre_info: Dict with tactic, technique, importance
        examples: Example localization files
    
    Returns:
        Dict with keys 'en' and 'ru' containing YAML content
    """
    # Prepare event summary
    event_summary = []
    for idx, event in enumerate(norm_fields_group):
        summary = f"Event {idx + 1} key fields:\n"
        # Include most relevant fields
        relevant_keys = [
            "subject.process.name", "subject.process.cmdline",
            "subject.account.name", "event_src.hostname",
            "object.process.name", "object.path",
            "dst.ip", "dst.port"
        ]
        for key in relevant_keys:
            if key in event:
                summary += f"  {key}: {event[key]}\n"
        event_summary.append(summary)
    
    events_text = "\n".join(event_summary)
    
    # Generate English localization
    system_prompt_en = """You are a technical writer for a SIEM system, creating localization files for security correlation rules.
Your output must be valid YAML following the exact format shown in examples.
Write in clear, technical English suitable for SOC analysts."""

    prompt_en = f"""Generate an English localization file (i18n_en.yaml) for a security correlation rule.

MITRE ATT&CK Classification:
- Tactic: {mitre_info['tactic']}
- Technique: {mitre_info['technique']}
- Importance: {mitre_info['importance']}

Event Information:
{events_text}

Example format (study the structure):
```yaml
{examples['en'][0] if examples['en'] else 'Description: The rule detects suspicious activity\\nEventDescriptions:\\n    - LocalizationId: corrname_Example\\n      EventDescription: User {{subject.account.name}} performed action on host {{event_src.host}}'}
```

Generate a localization file with:
1. Description: Brief explanation of what the rule detects (1-2 sentences)
2. EventDescriptions: List of event descriptions with LocalizationId and EventDescription
   - Use placeholders like {{subject.account.name}}, {{event_src.host}}, {{subject.process.cmdline}}, etc.
   - Create 1-2 event descriptions depending on event complexity
   - LocalizationId should be descriptive (e.g., corrname_ProcessCreation)

Output YAML only, no code blocks or explanations:"""

    yaml_en = call_llm(prompt_en, system_prompt_en)
    
    # Clean up response
    yaml_en = yaml_en.strip()
    if yaml_en.startswith("```yaml"):
        yaml_en = yaml_en.split("```yaml", 1)[1]
    if yaml_en.startswith("```"):
        yaml_en = yaml_en.split("```", 1)[1]
    if yaml_en.endswith("```"):
        yaml_en = yaml_en.rsplit("```", 1)[0]
    yaml_en = yaml_en.strip()
    
    # Generate Russian localization
    system_prompt_ru = """You are a technical writer for a SIEM system, creating Russian localization files for security correlation rules.
Your output must be valid YAML following the exact format shown in examples.
Write in clear, technical Russian suitable for SOC analysts."""

    prompt_ru = f"""Generate a Russian localization file (i18n_ru.yaml) for a security correlation rule.

MITRE ATT&CK Classification:
- Тактика: {mitre_info['tactic']}
- Техника: {mitre_info['technique']}
- Важность: {mitre_info['importance']}

Event Information:
{events_text}

Example format (study the structure):
```yaml
{examples['ru'][0] if examples['ru'] else 'Description: Правило обнаруживает подозрительную активность\\nEventDescriptions:\\n    - LocalizationId: corrname_Example\\n      EventDescription: Пользователь {{subject.account.name}} выполнил действие на узле {{event_src.host}}'}
```

Generate a localization file with:
1. Description: Brief explanation in Russian of what the rule detects (1-2 sentences)
2. EventDescriptions: List of event descriptions with LocalizationId and EventDescription
   - Use placeholders like {{subject.account.name}}, {{event_src.host}}, {{subject.process.cmdline}}, etc.
   - Create 1-2 event descriptions depending on event complexity
   - LocalizationId should match English version

Output YAML only, no code blocks or explanations:"""

    yaml_ru = call_llm(prompt_ru, system_prompt_ru)
    
    # Clean up response
    yaml_ru = yaml_ru.strip()
    if yaml_ru.startswith("```yaml"):
        yaml_ru = yaml_ru.split("```yaml", 1)[1]
    if yaml_ru.startswith("```"):
        yaml_ru = yaml_ru.split("```", 1)[1]
    if yaml_ru.endswith("```"):
        yaml_ru = yaml_ru.rsplit("```", 1)[0]
    yaml_ru = yaml_ru.strip()
    
    return {"en": yaml_en, "ru": yaml_ru}


def process_correlation(corr_dir: Path, examples: Dict):
    """Process a single correlation directory"""
    print(f"\nProcessing {corr_dir.name}...")
    
    tests_dir = corr_dir / "tests"
    if not tests_dir.exists():
        print(f"  No tests directory found")
        return
    
    # Group normalized events by i index
    groups = {}
    for norm_file in sorted(tests_dir.glob("norm_fields_*.json")):
        match = re.match(r'norm_fields_(\d+)_(\d+)\.json', norm_file.name)
        if not match:
            continue
        
        i, j = match.groups()
        if i not in groups:
            groups[i] = []
        
        with open(norm_file, 'r', encoding='utf-8') as f:
            groups[i].append(json.load(f))
    
    if not groups:
        print(f"  No normalized fields found")
        return
    
    # Process first group (assuming all events in correlation relate to same attack)
    first_group = groups[min(groups.keys())]
    
    try:
        # Task 2: Classify MITRE ATT&CK
        print(f"  Classifying MITRE ATT&CK...")
        mitre_info = classify_mitre_attack(first_group)
        
        # Save answers.json
        answers_file = corr_dir / "answers.json"
        with open(answers_file, 'w', encoding='utf-8') as f:
            json.dump(mitre_info, f, indent=2, ensure_ascii=False)
        print(f"  Created answers.json: {mitre_info['tactic']} / {mitre_info['technique']}")
        
        # Task 3: Generate localizations
        print(f"  Generating localization files...")
        localizations = generate_localization(first_group, mitre_info, examples)
        
        # Create i18n directory
        i18n_dir = corr_dir / "i18n"
        i18n_dir.mkdir(exist_ok=True)
        
        # Save English
        with open(i18n_dir / "i18n_en.yaml", 'w', encoding='utf-8') as f:
            f.write(localizations["en"])
        print(f"  Created i18n_en.yaml")
        
        # Save Russian
        with open(i18n_dir / "i18n_ru.yaml", 'w', encoding='utf-8') as f:
            f.write(localizations["ru"])
        print(f"  Created i18n_ru.yaml")
    
    except Exception as e:
        print(f"  Error: {e}")
        import traceback
        traceback.print_exc()


def process_all_correlations():
    """Process all correlation directories"""
    # Load example localizations
    print("Loading example localizations from macOS rules...")
    examples = load_example_localizations()
    print(f"Loaded {len(examples['en'])} examples")
    
    # Process each correlation
    for corr_dir in sorted(WINDOWS_RULES_DIR.glob("correlation_*")):
        if not corr_dir.is_dir():
            continue
        
        process_correlation(corr_dir, examples)


if __name__ == "__main__":
    import re
    
    print("="*60)
    print("Task 2 & 3: MITRE Classification and Localization")
    print("="*60)
    
    if not ANTHROPIC_API_KEY and not OPENAI_API_KEY:
        print("\nERROR: No API key configured!")
        print("Please set one of the following environment variables:")
        print("  export ANTHROPIC_API_KEY='your-key-here'")
        print("  export OPENAI_API_KEY='your-key-here'")
        exit(1)
    
    process_all_correlations()
    print("\nProcessing complete!")
