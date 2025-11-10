#!/usr/bin/env python3
"""
Улучшение классификации MITRE ATT&CK используя локальную Llama через Ollama
Быстро и без лимитов!
"""

import json
import subprocess
from pathlib import Path

def load_events(correlation_dir):
    """Загружает все события из correlation директории"""
    events = []
    tests_dir = correlation_dir / "tests"
    
    for events_file in sorted(tests_dir.glob("events_*.json")):
        with open(events_file, 'r', encoding='utf-8') as f:
            event_data = json.load(f)
            events.append(event_data)
    
    return events

def classify_with_ollama(events, model="llama3:8b"):
    """Классифицирует события используя локальную Llama через Ollama"""
    
    # Подготовка контекста
    events_summary = []
    for event in events[:3]:  # Берем первые 3 события для анализа
        if isinstance(event, dict):
            event_data = event.get('Event', event)
            system_data = event_data.get('System', {})
            event_id = system_data.get('EventID', 'Unknown')
            
            if 'EventData' in event_data:
                events_summary.append(f"EventID {event_id}: {json.dumps(event_data['EventData'])[:300]}")
    
    prompt = f"""Analyze these Windows security events and classify them according to MITRE ATT&CK framework.

Events:
{chr(10).join(events_summary)}

Determine:
1. MITRE ATT&CK Tactic (ONE from: Reconnaissance, Resource Development, Initial Access, Execution, Persistence, Privilege Escalation, Defense Evasion, Credential Access, Discovery, Lateral Movement, Collection, Command and Control, Exfiltration, Impact)

2. MITRE ATT&CK Technique (specific, e.g., "Create Account", "Process Injection", "PowerShell")

3. Importance (ONE: low, medium, high, critical)

Respond with ONLY valid JSON:
{{"tactic": "Tactic Name", "technique": "Technique Name", "importance": "level"}}"""

    try:
        # Вызов Ollama через subprocess
        result = subprocess.run(
            ["/usr/local/bin/ollama", "run", model, prompt],
            capture_output=True,
            text=True,
            timeout=30
        )
        
        if result.returncode != 0:
            print(f"❌ Ollama error: {result.stderr}")
            return None
        
        result_text = result.stdout.strip()
        
        # Извлекаем JSON из ответа
        if "```json" in result_text:
            result_text = result_text.split("```json")[1].split("```")[0].strip()
        elif "```" in result_text:
            result_text = result_text.split("```")[1].split("```")[0].strip()
        
        # Ищем JSON в тексте
        start_idx = result_text.find('{')
        end_idx = result_text.rfind('}') + 1
        
        if start_idx != -1 and end_idx > start_idx:
            result_text = result_text[start_idx:end_idx]
        
        classification = json.loads(result_text)
        
        # Если LLM вернул массив, берем первый элемент
        if isinstance(classification, list):
            classification = classification[0]
        
        return classification
        
    except subprocess.TimeoutExpired:
        print(f"⏱️  Timeout")
        return None
    except json.JSONDecodeError as e:
        print(f"❌ JSON error: {e}")
        print(f"   Response: {result_text[:100]}")
        return None
    except Exception as e:
        print(f"❌ Error: {e}")
        return None

def process_all_correlations(model="llama3:8b"):
    """Обрабатывает все корреляции"""
    base_dir = Path("windows_correlation_rules")
    
    if not base_dir.exists():
        print(f"❌ Directory not found: {base_dir}")
        return
    
    print(f"🚀 Starting classification with Ollama ({model})...\n")
    
    correlation_dirs = sorted([d for d in base_dir.iterdir() if d.is_dir() and d.name.startswith("correlation_")])
    
    total = len(correlation_dirs)
    improved = 0
    
    for idx, correlation_dir in enumerate(correlation_dirs, 1):
        correlation_name = correlation_dir.name
        print(f"[{idx}/{total}] {correlation_name}...", end=" ", flush=True)
        
        # Загружаем события
        events = load_events(correlation_dir)
        
        if not events:
            print("⚠️  No events")
            continue
        
        # Классифицируем с Ollama
        classification = classify_with_ollama(events, model)
        
        if classification and 'tactic' in classification and 'technique' in classification:
            # Сохраняем результат
            answers_file = correlation_dir / "answers.json"
            with open(answers_file, 'w', encoding='utf-8') as f:
                json.dump(classification, f, indent=2, ensure_ascii=False)
            
            tactic = classification.get('tactic', 'Unknown')[:30]
            technique = classification.get('technique', 'Unknown')[:40]
            print(f"✅ {tactic} / {technique}")
            improved += 1
        else:
            print("❌ Failed")
    
    print(f"\n{'='*60}")
    print(f"✅ Improved: {improved}/{total} correlations")
    print(f"{'='*60}")

if __name__ == "__main__":
    import sys
    
    # Можно указать модель как аргумент
    model = sys.argv[1] if len(sys.argv) > 1 else "llama3:8b"
    
    print(f"Using model: {model}")
    print(f"Available models: llama3:8b, deepseek-r1:8b, gemma:7b, phi3:14b\n")
    
    process_all_correlations(model)
    
    print("\n📦 Creating updated ZIP archive...")
    subprocess.run(["python3", "create_zip.py"])
    
    print("\n✅ Done! Now run:")
    print("   git add windows_correlation_rules.zip")
    print("   git commit -m 'Improve MITRE classification with local LLM'")
    print("   git push origin main")
