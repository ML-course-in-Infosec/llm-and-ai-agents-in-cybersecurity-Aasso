#!/usr/bin/env python3
"""
Quick heuristic-based MITRE ATT&CK classifier
Generates answers.json for all correlations based on command patterns
"""

import json
import re
from pathlib import Path
from typing import Dict, List

WINDOWS_RULES_DIR = Path("windows_correlation_rules")

# Pattern-based MITRE ATT&CK mappings
MITRE_PATTERNS = [
    # Credential Access - LSASS dumping
    {
        "patterns": [r"mimikatz", r"procdump.*lsass", r"sekurlsa", r"logonpasswords", r"rundll32.*comsvcs.*minidump"],
        "tactic": "Credential Access",
        "technique": "OS Credential Dumping: LSASS Memory",
        "importance": "high"
    },
    {
        "patterns": [r"reg.*save.*sam", r"reg.*save.*system", r"reg.*save.*security"],
        "tactic": "Credential Access",
        "technique": "OS Credential Dumping: Security Account Manager",
        "importance": "high"
    },
    # Credential Access - Generic
    {
        "patterns": [r"credentials", r"password", r"ntlm"],
        "tactic": "Credential Access",
        "technique": "Unsecured Credentials",
        "importance": "medium"
    },
    # Impact - Inhibit Recovery
    {
        "patterns": [r"vssadmin.*delete.*shadow", r"wbadmin.*delete", r"bcdedit.*recoveryenabled.*no"],
        "tactic": "Impact",
        "technique": "Inhibit System Recovery",
        "importance": "high"
    },
    # Persistence - Create Account
    {
        "patterns": [r"net.*user.*\/add", r"net.*localgroup.*administrators.*\/add", r"net\s+user\s+\w+\s+\/add"],
        "tactic": "Persistence",
        "technique": "Create Account",
        "importance": "high"
    },
    # Defense Evasion - PowerShell obfuscation
    {
        "patterns": [r"powershell.*-enc", r"powershell.*-encodedcommand", r"powershell.*-e\s+", r"powershell.*bypass.*execution"],
        "tactic": "Defense Evasion",
        "technique": "Obfuscated Files or Information",
        "importance": "medium"
    },
    {
        "patterns": [r"certutil.*-decode", r"certutil.*-urlcache", r"certutil.*-f"],
        "tactic": "Defense Evasion",
        "technique": "Deobfuscate/Decode Files or Information",
        "importance": "medium"
    },
    # Execution - PowerShell
    {
        "patterns": [r"powershell\.exe", r"pwsh\.exe"],
        "tactic": "Execution",
        "technique": "PowerShell",
        "importance": "medium"
    },
    # Execution - Scripting
    {
        "patterns": [r"wscript\.exe", r"cscript\.exe", r"mshta\.exe"],
        "tactic": "Execution",
        "technique": "Windows Script Host",
        "importance": "medium"
    },
    {
        "patterns": [r"schtasks.*\/create", r"at\s+\d+:\d+"],
        "tactic": "Execution",
        "technique": "Scheduled Task",
        "importance": "medium"
    },
    # Lateral Movement
    {
        "patterns": [r"psexec", r"wmic.*process.*call.*create", r"\\\\.*\\admin\$", r"\\\\.*\\c\$"],
        "tactic": "Lateral Movement",
        "technique": "Remote Services",
        "importance": "high"
    },
    # Discovery - Account/Group
    {
        "patterns": [r"net.*group", r"net.*localgroup", r"dsquery.*user"],
        "tactic": "Discovery",
        "technique": "Account Discovery",
        "importance": "low"
    },
    # Discovery - System Info
    {
        "patterns": [r"whoami", r"systeminfo", r"hostname", r"ipconfig"],
        "tactic": "Discovery",
        "technique": "System Information Discovery",
        "importance": "low"
    },
    # Discovery - Network/Share
    {
        "patterns": [r"net.*view", r"net.*share", r"net.*use"],
        "tactic": "Discovery",
        "technique": "Network Share Discovery",
        "importance": "low"
    },
    # Discovery - Process
    {
        "patterns": [r"tasklist", r"get-process", r"ps\s"],
        "tactic": "Discovery",
        "technique": "Process Discovery",
        "importance": "low"
    },
    # Privilege Escalation
    {
        "patterns": [r"runas", r"elevate", r"bypass.*uac"],
        "tactic": "Privilege Escalation",
        "technique": "Bypass User Account Control",
        "importance": "high"
    },
    # Defense Evasion - Process Injection
    {
        "patterns": [r"inject", r"shellcode", r"virtualalloc", r"writeprocessmemory"],
        "tactic": "Defense Evasion",
        "technique": "Process Injection",
        "importance": "high"
    },
    # Persistence - Registry Run Keys
    {
        "patterns": [r"reg.*add.*\\run", r"reg.*add.*\\runonce", r"currentversion\\run"],
        "tactic": "Persistence",
        "technique": "Registry Run Keys",
        "importance": "medium"
    },
    # Collection
    {
        "patterns": [r"clipboard", r"keylog", r"screenshot"],
        "tactic": "Collection",
        "technique": "Input Capture",
        "importance": "medium"
    },
]

# Event ID based classification
EVENT_ID_MAPPING = {
    # Sysmon events
    "1": {"tactic": "Execution", "technique": "Process Creation", "importance": "low"},
    "3": {"tactic": "Command and Control", "technique": "Network Connection", "importance": "low"},
    "10": {"tactic": "Credential Access", "technique": "Process Access", "importance": "medium"},
    "11": {"tactic": "Defense Evasion", "technique": "File Creation", "importance": "low"},
    "13": {"tactic": "Persistence", "technique": "Registry Event", "importance": "low"},
    
    # Windows Security events
    "4720": {"tactic": "Persistence", "technique": "Create Account", "importance": "high"},
    "4625": {"tactic": "Credential Access", "technique": "Brute Force", "importance": "medium"},
    "4624": {"tactic": "Initial Access", "technique": "Valid Accounts", "importance": "low"},
    "4688": {"tactic": "Execution", "technique": "Process Creation", "importance": "low"},
    "4648": {"tactic": "Lateral Movement", "technique": "Explicit Credentials", "importance": "medium"},
    "4672": {"tactic": "Privilege Escalation", "technique": "Special Privileges", "importance": "medium"},
    "4698": {"tactic": "Execution", "technique": "Scheduled Task", "importance": "medium"},
    "4776": {"tactic": "Credential Access", "technique": "NTLM Authentication", "importance": "low"},
}


def classify_events(norm_fields_list: List[Dict]) -> Dict[str, str]:
    """Classify based on normalized fields"""
    
    # Collect all command lines and process names
    all_text = ""
    event_ids = set()
    
    for fields in norm_fields_list:
        cmdline = fields.get("subject.process.cmdline", "")
        proc_name = fields.get("subject.process.name", "")
        parent_cmd = fields.get("subject.process.parent.cmdline", "")
        event_id = fields.get("event_src.id", "")
        
        all_text += f" {cmdline} {proc_name} {parent_cmd}".lower()
        if event_id:
            event_ids.add(event_id)
    
    # Try pattern matching
    for mapping in MITRE_PATTERNS:
        for pattern in mapping["patterns"]:
            if re.search(pattern, all_text, re.IGNORECASE):
                return {
                    "tactic": mapping["tactic"],
                    "technique": mapping["technique"],
                    "importance": mapping["importance"]
                }
    
    # Try event ID mapping
    for event_id in event_ids:
        if event_id in EVENT_ID_MAPPING:
            return EVENT_ID_MAPPING[event_id]
    
    # Default classification
    if "powershell" in all_text:
        return {
            "tactic": "Execution",
            "technique": "Command and Scripting Interpreter: PowerShell",
            "importance": "medium"
        }
    
    # Generic fallback
    return {
        "tactic": "Execution",
        "technique": "Command and Scripting Interpreter",
        "importance": "medium"
    }


def process_correlation(corr_dir: Path):
    """Generate answers.json for a correlation"""
    tests_dir = corr_dir / "tests"
    
    # Skip if answers.json already exists
    answers_file = corr_dir / "answers.json"
    if answers_file.exists():
        print(f"  Skipping (answers.json exists)")
        return
    
    # Collect all normalized events
    norm_files = sorted(tests_dir.glob("norm_fields_*.json"))
    if not norm_files:
        print(f"  No normalized files found")
        return
    
    # Read first group of events
    norm_fields_list = []
    for norm_file in norm_files[:5]:  # Read up to 5 events for context
        try:
            with open(norm_file, 'r', encoding='utf-8') as f:
                norm_fields_list.append(json.load(f))
        except Exception as e:
            print(f"  Error reading {norm_file.name}: {e}")
    
    if not norm_fields_list:
        return
    
    # Classify
    classification = classify_events(norm_fields_list)
    
    # Save answers.json
    with open(answers_file, 'w', encoding='utf-8') as f:
        json.dump(classification, f, indent=2, ensure_ascii=False)
    
    print(f"  Created answers.json: {classification['tactic']} / {classification['technique']}")


def main():
    print("="*60)
    print("Generating answers.json files for all correlations")
    print("="*60)
    
    for corr_dir in sorted(WINDOWS_RULES_DIR.glob("correlation_*")):
        if not corr_dir.is_dir():
            continue
        
        print(f"\nProcessing {corr_dir.name}...")
        try:
            process_correlation(corr_dir)
        except Exception as e:
            print(f"  Error: {e}")
    
    print("\n" + "="*60)
    print("Complete!")
    print("="*60)


if __name__ == "__main__":
    main()
