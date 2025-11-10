#!/usr/bin/env python3
"""
Solution for ML Course in Infosec - Homework Task 4
Processes Windows correlation rules:
1. Normalizes events to SIEM fields
2. Classifies MITRE ATT&CK tactic/technique
3. Generates i18n localization files
"""

import json
import os
import re
import yaml
from pathlib import Path
from typing import Dict, List, Any, Optional, Tuple
from datetime import datetime

# Configuration
WINDOWS_RULES_DIR = Path("windows_correlation_rules")
MACOS_RULES_DIR = Path("macos_correlation_rules")
TAXONOMY_DIR = Path("taxonomy_fields")


class EventNormalizer:
    """Normalizes Windows events to SIEM field schema"""
    
    def __init__(self, taxonomy_path: Path):
        self.taxonomy = self._load_taxonomy(taxonomy_path)
    
    def _load_taxonomy(self, path: Path) -> Dict:
        """Load SIEM field taxonomy"""
        with open(path / "i18n_en.yaml", 'r', encoding='utf-8') as f:
            return yaml.safe_load(f)
    
    def normalize_event(self, event: Dict) -> Dict:
        """Convert raw Windows event to normalized SIEM fields"""
        normalized = {}
        
        try:
            evt = event.get("Event", {})
            system = evt.get("System", {})
            event_data = evt.get("EventData", {})
            
            # Time
            time_created = system.get("TimeCreated", {})
            if isinstance(time_created, dict):
                system_time = time_created.get("SystemTime", "")
            else:
                system_time = ""
            if system_time:
                normalized["time"] = system_time.lower()
            
            # Event source information
            provider = system.get("Provider", {})
            if isinstance(provider, dict):
                provider_name = provider.get("Name", "")
                if provider_name:
                    normalized["event_src.title"] = provider_name.lower()
                    
                    # Determine subsystem
                    if "sysmon" in provider_name.lower():
                        normalized["event_src.subsys"] = "sysmon"
                        normalized["event_src.vendor"] = "microsoft"
                    elif "security" in provider_name.lower():
                        normalized["event_src.subsys"] = "security"
                        normalized["event_src.vendor"] = "microsoft"
                    elif "powershell" in provider_name.lower():
                        normalized["event_src.subsys"] = "powershell"
                        normalized["event_src.vendor"] = "microsoft"
                    else:
                        normalized["event_src.vendor"] = "microsoft"
            
            # Computer/Hostname
            computer = system.get("Computer", "")
            if computer:
                normalized["event_src.hostname"] = computer.lower()
            
            # Event ID
            event_id = system.get("EventID", "")
            if event_id:
                normalized["event_src.id"] = str(event_id).lower()
            
            # Channel
            channel = system.get("Channel", "")
            if channel:
                normalized["event_src.category"] = channel.lower()
            
            # Parse EventData
            if isinstance(event_data, dict):
                data_list = event_data.get("Data", [])
                if isinstance(data_list, list):
                    data_dict = {}
                    for item in data_list:
                        if isinstance(item, dict):
                            name = item.get("Name", "")
                            text = item.get("text", "")
                            if name:
                                data_dict[name] = text
                    
                    # Process fields based on EventID
                    self._process_sysmon_fields(normalized, data_dict, event_id)
                    self._process_security_fields(normalized, data_dict, event_id)
                    self._process_powershell_fields(normalized, data_dict, event_id)
        
        except Exception as e:
            print(f"Error normalizing event: {e}")
        
        return normalized
    
    def _process_sysmon_fields(self, normalized: Dict, data: Dict, event_id: Any):
        """Process Sysmon-specific fields"""
        # User account
        user = data.get("User", "")
        if user and "\\" in user:
            parts = user.split("\\", 1)
            normalized["subject.account.domain"] = parts[0].lower()
            normalized["subject.account.name"] = parts[1].lower()
        elif user:
            normalized["subject.account.name"] = user.lower()
        
        # Process information
        image = data.get("Image", "")
        if image:
            normalized["subject.process.fullpath"] = image.lower()
            # Extract path and name
            if "\\" in image or "/" in image:
                separator = "\\" if "\\" in image else "/"
                parts = image.rsplit(separator, 1)
                normalized["subject.process.path"] = parts[0].lower() + separator
                normalized["subject.process.name"] = parts[1].lower()
            else:
                normalized["subject.process.name"] = image.lower()
        
        # Original filename
        orig_filename = data.get("OriginalFileName", "")
        if orig_filename:
            normalized["subject.process.original_name"] = orig_filename.lower()
        
        # File version
        file_version = data.get("FileVersion", "")
        if file_version:
            normalized["subject.process.version"] = file_version.lower()
        
        # Command line
        cmdline = data.get("CommandLine", "")
        if cmdline:
            normalized["subject.process.cmdline"] = cmdline.lower()
        
        # Process ID and GUID
        proc_id = data.get("ProcessId", "")
        if proc_id:
            normalized["subject.process.id"] = str(proc_id).lower()
        
        proc_guid = data.get("ProcessGuid", "")
        if proc_guid:
            normalized["subject.process.guid"] = proc_guid.lower()
        
        # Current directory
        cwd = data.get("CurrentDirectory", "")
        if cwd:
            normalized["subject.process.cwd"] = cwd.lower()
        
        # Hashes
        hashes_str = data.get("Hashes", "")
        if hashes_str:
            self._parse_hashes(normalized, hashes_str, "subject.process")
        
        # Metadata
        description = data.get("Description", "")
        product = data.get("Product", "")
        company = data.get("Company", "")
        if description or product or company:
            meta_parts = []
            if description:
                meta_parts.append(f"description:{description}")
            if product:
                meta_parts.append(f"product:{product}")
            if company:
                meta_parts.append(f"company:{company}")
            normalized["subject.process.meta"] = " | ".join(meta_parts).lower()
        
        # Parent process
        parent_image = data.get("ParentImage", "")
        if parent_image:
            normalized["subject.process.parent.fullpath"] = parent_image.lower()
            if "\\" in parent_image or "/" in parent_image:
                separator = "\\" if "\\" in parent_image else "/"
                parts = parent_image.rsplit(separator, 1)
                normalized["subject.process.parent.path"] = parts[0].lower() + separator
                normalized["subject.process.parent.name"] = parts[1].lower()
            else:
                normalized["subject.process.parent.name"] = parent_image.lower()
        
        parent_cmdline = data.get("ParentCommandLine", "")
        if parent_cmdline:
            normalized["subject.process.parent.cmdline"] = parent_cmdline.lower()
        
        parent_id = data.get("ParentProcessId", "")
        if parent_id:
            normalized["subject.process.parent.id"] = str(parent_id).lower()
        
        parent_guid = data.get("ParentProcessGuid", "")
        if parent_guid:
            normalized["subject.process.parent.guid"] = parent_guid.lower()
        
        # Target process (for ProcessAccess events)
        target_image = data.get("TargetImage", "")
        if target_image:
            normalized["object.process.fullpath"] = target_image.lower()
            if "\\" in target_image or "/" in target_image:
                separator = "\\" if "\\" in target_image else "/"
                parts = target_image.rsplit(separator, 1)
                normalized["object.process.path"] = parts[0].lower() + separator
                normalized["object.process.name"] = parts[1].lower()
            else:
                normalized["object.process.name"] = target_image.lower()
        
        # Destination/Network fields
        dest_ip = data.get("DestinationIp", "")
        if dest_ip:
            normalized["dst.ip"] = dest_ip.lower()
        
        dest_port = data.get("DestinationPort", "")
        if dest_port:
            normalized["dst.port"] = str(dest_port).lower()
        
        dest_hostname = data.get("DestinationHostname", "")
        if dest_hostname:
            normalized["dst.hostname"] = dest_hostname.lower()
        
        # Registry fields
        target_object = data.get("TargetObject", "")
        if target_object:
            normalized["object.path"] = target_object.lower()
        
        # File fields
        target_filename = data.get("TargetFilename", "")
        if target_filename:
            normalized["object.path"] = target_filename.lower()
    
    def _process_security_fields(self, normalized: Dict, data: Dict, event_id: Any):
        """Process Windows Security log fields"""
        # Target account
        target_user = data.get("TargetUserName", "")
        if target_user:
            normalized["object.account.name"] = target_user.lower()
        
        target_domain = data.get("TargetDomainName", "")
        if target_domain:
            normalized["object.account.domain"] = target_domain.lower()
        
        target_sid = data.get("TargetUserSid", "") or data.get("TargetSid", "")
        if target_sid:
            normalized["object.account.id"] = target_sid.lower()
        
        # Subject account
        subject_user = data.get("SubjectUserName", "")
        if subject_user:
            normalized["subject.account.name"] = subject_user.lower()
        
        subject_domain = data.get("SubjectDomainName", "")
        if subject_domain:
            normalized["subject.account.domain"] = subject_domain.lower()
        
        subject_sid = data.get("SubjectUserSid", "")
        if subject_sid:
            normalized["subject.account.id"] = subject_sid.lower()
        
        # Logon information
        logon_type = data.get("LogonType", "")
        if logon_type:
            normalized["logon_type"] = str(logon_type).lower()
        
        logon_id = data.get("TargetLogonId", "") or data.get("LogonId", "")
        if logon_id:
            normalized["subject.account.session_id"] = str(logon_id).lower()
        
        # Workstation
        workstation = data.get("WorkstationName", "")
        if workstation:
            normalized["src.hostname"] = workstation.lower()
        
        # IP address
        ip_address = data.get("IpAddress", "")
        if ip_address and ip_address not in ["-", ""]:
            normalized["src.ip"] = ip_address.lower()
        
        # Process
        process_name = data.get("ProcessName", "")
        if process_name:
            normalized["subject.process.fullpath"] = process_name.lower()
    
    def _process_powershell_fields(self, normalized: Dict, data: Dict, event_id: Any):
        """Process PowerShell log fields"""
        # Script block text
        script_block = data.get("ScriptBlockText", "")
        if script_block:
            normalized["object.value"] = script_block.lower()
        
        # Command
        command = data.get("HostApplication", "")
        if command:
            normalized["subject.process.cmdline"] = command.lower()
    
    def _parse_hashes(self, normalized: Dict, hashes_str: str, prefix: str):
        """Parse hash string into individual hash fields"""
        # Format: SHA1=XXX,MD5=YYY,SHA256=ZZZ,IMPHASH=AAA
        hash_dict = {}
        for part in hashes_str.split(","):
            if "=" in part:
                algo, value = part.split("=", 1)
                hash_dict[algo.strip().upper()] = value.strip()
        
        if "MD5" in hash_dict:
            normalized[f"{prefix}.hash.md5"] = hash_dict["MD5"].lower()
        if "SHA1" in hash_dict:
            normalized[f"{prefix}.hash.sha1"] = hash_dict["SHA1"].lower()
        if "SHA256" in hash_dict:
            normalized[f"{prefix}.hash.sha256"] = hash_dict["SHA256"].lower()
        if "IMPHASH" in hash_dict:
            normalized[f"{prefix}.hash.imphash"] = hash_dict["IMPHASH"].lower()


def normalize_all_events(base_dir: Path, taxonomy_dir: Path):
    """Process all correlation directories and normalize events"""
    normalizer = EventNormalizer(taxonomy_dir)
    
    # Process each correlation directory
    for corr_dir in sorted(base_dir.glob("correlation_*")):
        if not corr_dir.is_dir():
            continue
        
        print(f"Processing {corr_dir.name}...")
        tests_dir = corr_dir / "tests"
        
        if not tests_dir.exists():
            print(f"  No tests directory found")
            continue
        
        # Process all events_*.json files
        for events_file in sorted(tests_dir.glob("events_*.json")):
            # Extract i and j from filename
            match = re.match(r'events_(\d+)_(\d+)\.json', events_file.name)
            if not match:
                continue
            
            i, j = match.groups()
            norm_file = tests_dir / f"norm_fields_{i}_{j}.json"
            
            # Read event
            try:
                with open(events_file, 'r', encoding='utf-8') as f:
                    event = json.load(f)
                
                # Normalize
                normalized = normalizer.normalize_event(event)
                
                # Write normalized fields
                with open(norm_file, 'w', encoding='utf-8') as f:
                    json.dump(normalized, f, indent=2, ensure_ascii=False)
                
                print(f"  Created {norm_file.name}")
            
            except Exception as e:
                print(f"  Error processing {events_file.name}: {e}")


if __name__ == "__main__":
    print("="*60)
    print("Task 1: Normalizing Events")
    print("="*60)
    normalize_all_events(WINDOWS_RULES_DIR, TAXONOMY_DIR)
    print("\nNormalization complete!")
