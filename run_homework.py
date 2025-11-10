#!/usr/bin/env python3
"""
Main script to execute all homework tasks
Run this script to process all correlation rules
"""

import subprocess
import sys
from pathlib import Path

def run_task(script_name: str, description: str):
    """Run a task script"""
    print("\n" + "="*70)
    print(f"{description}")
    print("="*70 + "\n")
    
    result = subprocess.run(
        [sys.executable, script_name],
        cwd=Path(__file__).parent
    )
    
    if result.returncode != 0:
        print(f"\n⚠️  {script_name} exited with code {result.returncode}")
        return False
    return True

def main():
    print("""
╔══════════════════════════════════════════════════════════════╗
║   ML Course in InfoSec - Homework Task 4 Solution           ║
║   Processing Windows Correlation Rules                       ║
╚══════════════════════════════════════════════════════════════╝
""")
    
    # Task 1: Normalize events
    if not run_task("process_correlations.py", "TASK 1: Normalizing Events to SIEM Fields"):
        print("❌ Task 1 failed. Check errors above.")
        return
    
    print("\n✅ Task 1 completed successfully!")
    
    # Task 2 & 3: MITRE classification and localization (requires API key)
    print("\n" + "="*70)
    print("TASK 2 & 3: MITRE Classification and Localization Generation")
    print("="*70)
    print("\n⚠️  These tasks require an API key for LLM (Claude or GPT-4)")
    print("Set environment variable: ANTHROPIC_API_KEY or OPENAI_API_KEY")
    
    response = input("\nDo you want to run Tasks 2 & 3 now? (y/n): ")
    
    if response.lower() == 'y':
        if not run_task("classify_and_localize.py", "Running MITRE Classification and Localization"):
            print("❌ Tasks 2 & 3 failed. Check errors above.")
            return
        print("\n✅ Tasks 2 & 3 completed successfully!")
    else:
        print("\nℹ️  Skipping Tasks 2 & 3. You can run classify_and_localize.py later.")
    
    print("\n" + "="*70)
    print("📦 Packaging Results")
    print("="*70)
    
    # Create ZIP file
    import zipfile
    import os
    
    zip_path = Path("windows_correlation_rules.zip")
    print(f"\nCreating {zip_path}...")
    
    with zipfile.ZipFile(zip_path, 'w', zipfile.ZIP_DEFLATED) as zipf:
        base_dir = Path("windows_correlation_rules")
        for corr_dir in sorted(base_dir.glob("correlation_*")):
            if not corr_dir.is_dir():
                continue
            
            # Add all files in correlation directory
            for file_path in corr_dir.rglob("*"):
                if file_path.is_file():
                    arcname = file_path.relative_to(base_dir.parent)
                    zipf.write(file_path, arcname)
                    
    print(f"✅ Created {zip_path}")
    print(f"   Size: {zip_path.stat().st_size / 1024 / 1024:.2f} MB")
    
    print("\n" + "="*70)
    print("🎉 ALL TASKS COMPLETED!")
    print("="*70)
    print(f"""
Next steps:
1. Review the generated files in windows_correlation_rules/
2. Upload windows_correlation_rules.zip to your GitHub repository
3. Commit and push to trigger autograder

Files generated:
  - tests/norm_fields_*.json (Task 1)
  - answers.json (Task 2)
  - i18n/i18n_en.yaml (Task 3)
  - i18n/i18n_ru.yaml (Task 3)
""")

if __name__ == "__main__":
    main()
