# Quick Reference - Homework Task 4

## 📦 Main Deliverable
**File**: `windows_correlation_rules.zip` (548 KB)  
**Location**: `/Users/aasso/Desktop/ML_course_in_Infosec/`  
**Status**: ✅ READY FOR SUBMISSION

## 🎯 What Was Completed

### Task 1: Event Normalization ✅
- **Script**: `process_correlations.py`
- **Output**: 528 `norm_fields_*.json` files
- **Method**: Rule-based mapping to SIEM taxonomy
- **Key**: All values lowercased, comprehensive field extraction

### Task 2: MITRE ATT&CK Classification ✅
- **Script**: `generate_answers.py`
- **Output**: 54 `answers.json` files
- **Method**: Pattern-based heuristic matching
- **Format**: `{"tactic": "...", "technique": "...", "importance": "..."}`

### Task 3: Localization Generation ✅
- **Script**: `generate_i18n.py`
- **Output**: 108 YAML files (54 EN + 54 RU)
- **Method**: Template-based with technique descriptions
- **Format**: Standard YAML with Description + EventDescriptions

## 📂 ZIP Structure

```
windows_correlation_rules.zip/
├── correlation_1/
│   ├── answers.json              # MITRE classification
│   ├── i18n/
│   │   ├── i18n_en.yaml         # English
│   │   └── i18n_ru.yaml         # Russian
│   └── tests/
│       ├── events_1_1.json      # Original (included)
│       └── norm_fields_1_1.json # Normalized
├── correlation_2/
│   └── ... (same structure)
...
└── correlation_54/
    └── ... (same structure)
```

## 🚀 Submission Commands

```bash
cd /Users/aasso/Desktop/ML_course_in_Infosec

git add windows_correlation_rules.zip
git commit -m "Add homework task 4 solution"
git push origin main
```

## 📊 By The Numbers

| Item | Count |
|------|-------|
| Correlations | 54 |
| Normalized Events | 528 |
| answers.json | 54 |
| i18n files (EN+RU) | 108 |
| **Total Files** | **746** |
| **ZIP Size** | **548 KB** |

## 🔧 Scripts Available

1. `process_correlations.py` - Normalize events (Task 1)
2. `generate_answers.py` - Create answers.json (Task 2)
3. `generate_i18n.py` - Generate localizations (Task 3)
4. `create_zip.py` - Package for submission
5. `classify_and_localize.py` - LLM-enhanced version (optional)
6. `run_homework.py` - Run all tasks

## ⚡ Re-run If Needed

```bash
# Re-normalize all events
python process_correlations.py

# Re-generate answers.json
python generate_answers.py

# Re-generate i18n files
python generate_i18n.py

# Re-create ZIP
python create_zip.py
```

## 🎓 Evaluation Metrics

- **Task 1**: Precision/Recall (exact field+value match, lowercase)
- **Task 2**: Accuracy (tactic, technique, importance separately)
- **Task 3**: BERTScore (semantic similarity of descriptions)

## 💡 Enhancement Option

For better Task 2 & 3 results with LLM:

```bash
export ANTHROPIC_API_KEY="sk-ant-..."
python classify_and_localize.py
```

Cost: ~$0.50-1.00 for all 54 correlations

## ✅ Checklist

- [x] All events normalized
- [x] All answers.json created
- [x] All i18n files generated
- [x] ZIP file created and verified
- [x] Documentation complete
- [ ] Uploaded to GitHub
- [ ] Autograder passed

## 📞 Files to Review

- `README.md` - Full documentation
- `SOLUTION_SUMMARY.md` - Detailed completion report
- This file - Quick reference

---

**Ready to submit!** Upload `windows_correlation_rules.zip` to GitHub.
