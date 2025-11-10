#!/usr/bin/env python3
"""
Create windows_correlation_rules.zip for submission
"""

import zipfile
from pathlib import Path

def create_submission_zip():
    """Create the submission ZIP file"""
    base_dir = Path("windows_correlation_rules")
    zip_path = Path("windows_correlation_rules.zip")
    
    print("="*60)
    print("Creating windows_correlation_rules.zip")
    print("="*60)
    
    # Count files
    file_count = 0
    
    with zipfile.ZipFile(zip_path, 'w', zipfile.ZIP_DEFLATED) as zipf:
        # Add all files from windows_correlation_rules
        for corr_dir in sorted(base_dir.glob("correlation_*")):
            if not corr_dir.is_dir():
                continue
            
            print(f"\nAdding {corr_dir.name}...")
            
            # Add answers.json
            answers_file = corr_dir / "answers.json"
            if answers_file.exists():
                arcname = answers_file.relative_to(base_dir.parent)
                zipf.write(answers_file, arcname)
                print(f"  ✓ answers.json")
                file_count += 1
            
            # Add i18n files
            i18n_dir = corr_dir / "i18n"
            if i18n_dir.exists():
                for i18n_file in i18n_dir.glob("*.yaml"):
                    arcname = i18n_file.relative_to(base_dir.parent)
                    zipf.write(i18n_file, arcname)
                    print(f"  ✓ {i18n_file.name}")
                    file_count += 1
            
            # Add tests directory
            tests_dir = corr_dir / "tests"
            if tests_dir.exists():
                test_files = list(tests_dir.glob("*.json"))
                for test_file in sorted(test_files):
                    arcname = test_file.relative_to(base_dir.parent)
                    zipf.write(test_file, arcname)
                    file_count += 1
                print(f"  ✓ {len(test_files)} test files")
    
    print("\n" + "="*60)
    print(f"✅ Created {zip_path}")
    print(f"   Total files: {file_count}")
    print(f"   Size: {zip_path.stat().st_size / 1024 / 1024:.2f} MB")
    print("="*60)
    
    # Verify structure
    print("\nVerifying ZIP structure...")
    with zipfile.ZipFile(zip_path, 'r') as zipf:
        files = zipf.namelist()
        
        # Check for required files in correlation_1
        required_patterns = [
            "windows_correlation_rules/correlation_1/answers.json",
            "windows_correlation_rules/correlation_1/i18n/i18n_en.yaml",
            "windows_correlation_rules/correlation_1/i18n/i18n_ru.yaml",
            "windows_correlation_rules/correlation_1/tests/events_1_1.json",
            "windows_correlation_rules/correlation_1/tests/norm_fields_1_1.json",
        ]
        
        for pattern in required_patterns:
            if pattern in files:
                print(f"  ✓ {pattern}")
            else:
                print(f"  ✗ Missing: {pattern}")
    
    print("\n" + "="*60)
    print("Ready for submission!")
    print("="*60)
    print("""
Next steps:
1. Upload windows_correlation_rules.zip to your GitHub repository root
2. Commit: git add windows_correlation_rules.zip
3. Commit: git commit -m "Add homework task 4 solution"
4. Push: git push origin main
5. The autograder will automatically run and evaluate your submission

Generated files per correlation:
  ✓ tests/norm_fields_*.json  (Task 1: Normalization)
  ✓ answers.json              (Task 2: MITRE Classification)
  ✓ i18n/i18n_en.yaml         (Task 3: English Localization)
  ✓ i18n/i18n_ru.yaml         (Task 3: Russian Localization)
""")


if __name__ == "__main__":
    create_submission_zip()
