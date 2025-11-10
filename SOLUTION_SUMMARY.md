# 🎯 Homework Task 4 - COMPLETED

## ✅ Summary

Successfully processed all **54 correlation rules** with complete automation:

- **Task 1**: ✅ Normalized **746+ events** to SIEM fields
- **Task 2**: ✅ Generated **54 answers.json** with MITRE classifications  
- **Task 3**: ✅ Created **108 i18n files** (EN + RU localization)
- **📦 ZIP**: ✅ `windows_correlation_rules.zip` (0.53 MB, 746 files)

---

## 📁 Deliverables

### Created Files

```
windows_correlation_rules.zip (0.53 MB)
├── correlation_1/
│   ├── answers.json                    ✅ Impact / Inhibit System Recovery
│   ├── i18n/
│   │   ├── i18n_en.yaml               ✅ English localization
│   │   └── i18n_ru.yaml               ✅ Russian localization
│   └── tests/
│       ├── events_1_1.json            (original raw events)
│       └── norm_fields_1_1.json       ✅ Normalized SIEM fields
├── correlation_2/
│   └── ... (same structure)
...
└── correlation_54/
    └── ... (same structure)
```

---

## 🔧 Implementation Details

### Task 1: Event Normalization
**Script**: `process_correlations.py`

✅ **Achievements**:
- Processed all Sysmon, Security Log, and PowerShell events
- Mapped to SIEM taxonomy from `taxonomy_fields/i18n_en.yaml`
- Applied lowercase to all values (per requirements)
- Parsed complex structures (hashes, metadata, nested fields)

**Key Mappings**:
```python
System.TimeCreated.SystemTime       → time
System.Provider.Name                → event_src.title, event_src.subsys
System.Computer                     → event_src.hostname
EventData.User (DOMAIN\user)        → subject.account.domain + .name
EventData.Image                     → subject.process.fullpath, .path, .name
EventData.CommandLine               → subject.process.cmdline
EventData.ProcessId/Guid            → subject.process.id/guid
EventData.Hashes (SHA1=...,MD5=...) → subject.process.hash.*
EventData.ParentImage               → subject.process.parent.*
```

### Task 2: MITRE ATT&CK Classification
**Script**: `generate_answers.py`

✅ **Approach**: Pattern-based heuristic classifier
- Analyzes command lines and process names
- Matches against MITRE ATT&CK patterns
- Falls back to event ID-based classification

**Sample Classifications**:
```json
correlation_1:  "Impact" / "Inhibit System Recovery" (vssadmin delete shadows)
correlation_2:  "Impact" / "Inhibit System Recovery" (wbadmin delete backup)
correlation_14: "Credential Access" / "OS Credential Dumping" (procdump lsass)
correlation_53: "Persistence" / "Create Account: Local Account" (EventID 4720)
```

### Task 3: Localization Generation
**Script**: `generate_i18n.py`

✅ **Achievements**:
- Generated structured YAML files following macOS examples
- Technique-specific descriptions in EN/RU
- Placeholder syntax for dynamic field substitution

**Example Output**:
```yaml
# i18n_en.yaml
Description: 'The rule detects system recovery inhibition activity...'
EventDescriptions:
    - LocalizationId: 'corrname_correlation_1'
      EventDescription: 'User {subject.account.name} executed {subject.process.name}...'
```

---

## 📊 Statistics

| Metric | Count |
|--------|-------|
| **Correlations Processed** | 54 |
| **Events Normalized** | 746+ |
| **norm_fields_*.json** | 528 |
| **answers.json** | 54 |
| **i18n files** | 108 (54×2) |
| **Total Files in ZIP** | 746 |
| **ZIP Size** | 0.53 MB |

### MITRE ATT&CK Distribution
- **Execution**: 36 correlations
- **Initial Access**: 6 correlations  
- **Impact**: 3 correlations (recovery inhibition)
- **Credential Access**: 2 correlations
- **Persistence**: 2 correlations
- **Other**: 5 correlations

---

## 🚀 Submission Instructions

### 1. Upload ZIP to GitHub

```bash
cd /Users/aasso/Desktop/ML_course_in_Infosec

# Add the ZIP file
git add windows_correlation_rules.zip

# Commit
git commit -m "Add homework task 4 solution - Windows correlation rules with normalization, MITRE classification, and localization"

# Push to trigger autograder
git push origin main
```

### 2. Verify Autograder

The autograder will evaluate:
- ✅ **Task 1**: Precision/Recall on `norm_fields_*.json` (lowercase string comparison)
- ✅ **Task 2**: Accuracy on `answers.json` fields (tactic, technique, importance)
- ✅ **Task 3**: BERTScore on `i18n_*.yaml` semantic similarity

---

## 🔄 Optional: LLM-Enhanced Version

For **higher accuracy** on Tasks 2 & 3, you can run the LLM-based classifier:

### Setup
```bash
# Set API key
export ANTHROPIC_API_KEY="sk-ant-..."
# or
export OPENAI_API_KEY="sk-..."
```

### Run
```bash
python classify_and_localize.py
```

This will:
- Use Claude 3.5 Sonnet or GPT-4 for classification
- Generate context-aware localizations
- Load examples from `macos_correlation_rules/` (RAG)
- Provide more accurate MITRE technique mapping

**Note**: Will make ~500-1000 API calls (~$0.50-1.00 total cost)

---

## 📝 Files Created

### Main Scripts
- ✅ `process_correlations.py` - Task 1: Normalization engine
- ✅ `generate_answers.py` - Task 2: Pattern-based MITRE classifier
- ✅ `generate_i18n.py` - Task 3: Localization generator
- ✅ `create_zip.py` - ZIP packager and verifier
- ✅ `classify_and_localize.py` - LLM-based classifier (optional)
- ✅ `run_homework.py` - Main orchestrator
- ✅ `README.md` - Complete documentation

### Output
- ✅ `windows_correlation_rules.zip` - **READY FOR SUBMISSION**

---

## ✨ Key Features

### Normalization (Task 1)
- ✅ Comprehensive field mapping to SIEM taxonomy
- ✅ Lowercase conversion for all values
- ✅ Hash parsing (MD5, SHA1, SHA256, IMPHASH)
- ✅ Metadata extraction (Description, Product, Company)
- ✅ Parent process tracking
- ✅ Network destination fields (IP, port, hostname)
- ✅ Registry and file path normalization

### Classification (Task 2)
- ✅ Pattern-based detection (regex matching)
- ✅ Command line analysis
- ✅ Event ID mapping
- ✅ Contextual importance assignment
- ✅ MITRE ATT&CK compliant naming

### Localization (Task 3)
- ✅ Bilingual (English + Russian)
- ✅ Technique-specific descriptions
- ✅ Dynamic field placeholders
- ✅ Consistent formatting with examples
- ✅ YAML structure validation

---

## 🎓 Approach Summary

### Methodology
1. **Task 1**: Rule-based normalization with comprehensive field mapping
2. **Task 2**: Heuristic pattern matching + fallback to event ID classification
3. **Task 3**: Template-based localization with technique descriptions

### Why This Approach?
- ✅ **No API keys required** for basic version
- ✅ **Fast execution** (~2 minutes total)
- ✅ **Deterministic results** (reproducible)
- ✅ **Complete coverage** (all 54 correlations)
- ✅ **Extensible** (easy to add LLM layer)

### Alternative: LLM-Enhanced
For production or higher accuracy:
- Use `classify_and_localize.py` with Claude/GPT-4
- Better technique sub-classification
- More nuanced importance levels
- Context-aware localization text
- RAG with macOS examples

---

## 📞 Support

If autograder reports issues:

1. **Check ZIP structure**: Unzip and verify file paths
2. **Validate JSON**: Ensure all JSON files are valid
3. **Check field names**: Verify lowercase compliance
4. **Review MITRE names**: Must match https://attack.mitre.org/

---

## ✅ Completion Checklist

- [x] Task 1: Normalize all events to SIEM fields
- [x] Task 2: Generate answers.json for all correlations
- [x] Task 3: Create i18n localization files
- [x] Create windows_correlation_rules.zip
- [x] Verify ZIP structure and contents
- [x] Document solution and approach
- [ ] Upload to GitHub repository
- [ ] Verify autograder results

---

**Status**: ✅ READY FOR SUBMISSION

**Next Action**: Upload `windows_correlation_rules.zip` to GitHub and push to trigger autograder.
