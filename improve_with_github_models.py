#!/usr/bin/env python3
"""
Улучшение классификации MITRE ATT&CK используя GitHub Models (GPT-4o)
"""

import json
import os
import time
from pathlib import Path
from openai import OpenAI

# Настройка клиента для GitHub Models
client = OpenAI(
    base_url="https://models.inference.ai.azure.com",
    api_key=os.getenv("GITHUB_TOKEN")
)

def load_events(correlation_dir):
    """Загружает все события из correlation директории"""
    events = []
    tests_dir = correlation_dir / "tests"
    
    for events_file in sorted(tests_dir.glob("events_*.json")):
        with open(events_file, 'r', encoding='utf-8') as f:
            event_data = json.load(f)
            events.append(event_data)
    
    return events

def classify_with_llm(events):
    """Классифицирует события используя GPT-4o через GitHub Models"""
    
    # Подготовка контекста
    events_summary = []
    for event in events[:3]:  # Берем первые 3 события для анализа
        if isinstance(event, dict):
            event_data = event.get('Event', event)
            system_data = event_data.get('System', {})
            event_id = system_data.get('EventID', 'Unknown')
            
            if 'EventData' in event_data:
                events_summary.append(f"EventID {event_id}: {json.dumps(event_data['EventData'])[:500]}")
    
    prompt = f"""Analyze these Windows security events and classify them according to MITRE ATT&CK framework.

Events:
{chr(10).join(events_summary)}

Based on these events, determine:
1. MITRE ATT&CK Tactic (choose ONE from: Reconnaissance, Resource Development, Initial Access, Execution, Persistence, Privilege Escalation, Defense Evasion, Credential Access, Discovery, Lateral Movement, Collection, Command and Control, Exfiltration, Impact)

2. MITRE ATT&CK Technique (be specific, e.g., "Create Account", "Process Injection", "PowerShell", etc.)

3. Importance level (choose ONE: low, medium, high, critical)

Respond with ONLY valid JSON in this exact format:
{{"tactic": "Tactic Name", "technique": "Technique Name", "importance": "level"}}"""

    max_retries = 3
    for attempt in range(max_retries):
        try:
            response = client.chat.completions.create(
                model="gpt-4o",
                messages=[
                    {"role": "system", "content": "You are a cybersecurity expert specializing in MITRE ATT&CK classification. Always respond with valid JSON only."},
                    {"role": "user", "content": prompt}
                ],
                temperature=0.3,
                max_tokens=200
            )
            
            result_text = response.choices[0].message.content
            if result_text:
                result_text = result_text.strip()
            else:
                raise ValueError("Empty response from LLM")
            
            # Извлекаем JSON из ответа
            if "```json" in result_text:
                result_text = result_text.split("```json")[1].split("```")[0].strip()
            elif "```" in result_text:
                result_text = result_text.split("```")[1].split("```")[0].strip()
            
            result = json.loads(result_text)
            
            # Если LLM вернул массив, берем первый элемент
            if isinstance(result, list):
                result = result[0]
            
            return result
            
        except Exception as e:
            if "429" in str(e) or "Too Many Requests" in str(e):
                wait_time = (attempt + 1) * 10  # 10, 20, 30 секунд
                print(f"⏳ Rate limit, waiting {wait_time}s...")
                time.sleep(wait_time)
            elif attempt == max_retries - 1:
                print(f"❌ Error: {e}")
                return None
            else:
                time.sleep(2)
    
    return None

def process_all_correlations():
    """Обрабатывает все корреляции"""
    base_dir = Path("windows_correlation_rules")
    
    if not base_dir.exists():
        print(f"❌ Directory not found: {base_dir}")
        return
    
    print("🚀 Starting improved classification with GitHub Models (GPT-4o)...\n")
    
    correlation_dirs = sorted([d for d in base_dir.iterdir() if d.is_dir() and d.name.startswith("correlation_")])
    
    total = len(correlation_dirs)
    improved = 0
    
    for idx, correlation_dir in enumerate(correlation_dirs, 1):
        correlation_name = correlation_dir.name
        print(f"[{idx}/{total}] Processing {correlation_name}...", end=" ")
        
        # Загружаем события
        events = load_events(correlation_dir)
        
        if not events:
            print("⚠️  No events found")
            continue
        
        # Классифицируем с LLM
        classification = classify_with_llm(events)
        
        if classification:
            # Сохраняем результат
            answers_file = correlation_dir / "answers.json"
            with open(answers_file, 'w', encoding='utf-8') as f:
                json.dump(classification, f, indent=2, ensure_ascii=False)
            
            print(f"✅ {classification['tactic']} / {classification['technique']}")
            improved += 1
        else:
            print("❌ Failed")
        
        # Задержка между запросами для соблюдения rate limits
        time.sleep(2)
    
    print(f"\n{'='*60}")
    print(f"✅ Improved: {improved}/{total} correlations")
    print(f"{'='*60}")

if __name__ == "__main__":
    if not os.getenv("GITHUB_TOKEN"):
        print("❌ ERROR: GITHUB_TOKEN not set!")
        print("   export GITHUB_TOKEN='your-token-here'")
        exit(1)
    
    process_all_correlations()
    
    print("\n📦 Creating updated ZIP archive...")
    import subprocess
    subprocess.run([
        "python3", "create_zip.py"
    ])
    
    print("\n✅ Done! Now run:")
    print("   git add windows_correlation_rules.zip")
    print("   git commit -m 'Improve MITRE classification with LLM'")
    print("   git push origin main")
