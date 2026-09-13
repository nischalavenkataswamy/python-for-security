# Python for Security Automation 🐍

## Overview
A collection of Python scripts for security 
automation, IOC analysis, and SOC workflows — 
designed to reduce manual analyst workload 
and accelerate incident response.

---

## Scripts in This Repository

| Script | Purpose | Key Libraries |
|--------|---------|---------------|
| phishing_analyser.py | Analyse suspicious emails | requests, re |
| ioc_checker.py | Check IOCs against VirusTotal | requests, json |
| log_parser.py | Parse Windows event logs | xml, csv |
| hash_checker.py | Verify file integrity | hashlib |
| port_scanner.py | Basic network port scanner | socket, threading |

---

## Script 1 — IOC Checker

Checks IP addresses, domains, and file hashes 
against the VirusTotal API automatically.

```python
import requests
import json

API_KEY = "your_virustotal_api_key"
BASE_URL = "https://www.virustotal.com/api/v3"

def check_ip(ip_address):
    """Check IP reputation on VirusTotal"""
    headers = {"x-apikey": API_KEY}
    url = f"{BASE_URL}/ip_addresses/{ip_address}"
    
    response = requests.get(url, headers=headers)
    data = response.json()
    
    malicious = data["data"]["attributes"]\
                ["last_analysis_stats"]["malicious"]
    harmless = data["data"]["attributes"]\
               ["last_analysis_stats"]["harmless"]
    
    print(f"\n[*] IP: {ip_address}")
    print(f"[!] Malicious detections: {malicious}")
    print(f"[+] Harmless detections:  {harmless}")
    
    if malicious > 0:
        print(f"[ALERT] This IP is flagged as MALICIOUS")
    else:
        print(f"[INFO] This IP appears clean")

def check_hash(file_hash):
    """Check file hash reputation on VirusTotal"""
    headers = {"x-apikey": API_KEY}
    url = f"{BASE_URL}/files/{file_hash}"
    
    response = requests.get(url, headers=headers)
    data = response.json()
    
    malicious = data["data"]["attributes"]\
                ["last_analysis_stats"]["malicious"]
    
    print(f"\n[*] Hash: {file_hash}")
    print(f"[!] Malicious detections: {malicious}")
    
    if malicious > 0:
        print(f"[ALERT] File hash is flagged as MALICIOUS")
    else:
        print(f"[INFO] File hash appears clean")

def check_domain(domain):
    """Check domain reputation on VirusTotal"""
    headers = {"x-apikey": API_KEY}
    url = f"{BASE_URL}/domains/{domain}"
    
    response = requests.get(url, headers=headers)
    data = response.json()
    
    malicious = data["data"]["attributes"]\
                ["last_analysis_stats"]["malicious"]
    
    print(f"\n[*] Domain: {domain}")
    print(f"[!] Malicious detections: {malicious}")
    
    if malicious > 0:
        print(f"[ALERT] Domain is flagged as MALICIOUS")
    else:
        print(f"[INFO] Domain appears clean")

# Example usage
if __name__ == "__main__":
    check_ip("185.220.101.45")
    check_domain("evil-c2-server.com")
    check_hash("44d88612fea8a8f36de82e1278abb02f")
```

---

## Script 2 — Log Parser

Parses Windows Security event logs and 
extracts authentication events for analysis.

```python
import xml.etree.ElementTree as ET
import csv
from datetime import datetime

def parse_windows_events(log_file):
    """Parse Windows event log XML and extract key fields"""
    
    events = []
    tree = ET.parse(log_file)
    root = tree.getroot()
    
    for event in root.findall('.//Event'):
        event_id = event.find('.//EventID').text
        time_created = event.find('.//TimeCreated')\
                       .get('SystemTime')
        
        # Extract EventData fields
        event_data = {}
        for data in event.findall('.//Data'):
            name = data.get('Name')
            value = data.text
            if name:
                event_data[name] = value
        
        events.append({
            'EventID': event_id,
            'TimeCreated': time_created,
            'User': event_data.get('TargetUserName'),
            'SourceIP': event_data.get('IpAddress'),
            'LogonType': event_data.get('LogonType')
        })
    
    return events

def detect_brute_force(events, threshold=10):
    """Detect brute force from parsed events"""
    
    failed_logins = {}
    
    for event in events:
        if event['EventID'] == '4625':
            ip = event['SourceIP']
            if ip:
                failed_logins[ip] = \
                    failed_logins.get(ip, 0) + 1
    
    print("\n[*] Brute Force Detection Results:")
    for ip, count in failed_logins.items():
        if count >= threshold:
            print(f"[ALERT] {ip} — {count} failed attempts")

# Example usage
if __name__ == "__main__":
    events = parse_windows_events("security_log.xml")
    detect_brute_force(events, threshold=10)
```

---

## Script 3 — Hash Checker

Generates and verifies file hashes for 
forensic integrity verification.

```python
import hashlib
import os

def generate_hashes(file_path):
    """Generate MD5, SHA1, and SHA256 hashes"""
    
    hashes = {
        'MD5': hashlib.md5(),
        'SHA1': hashlib.sha1(),
        'SHA256': hashlib.sha256()
    }
    
    with open(file_path, 'rb') as f:
        while chunk := f.read(8192):
            for hash_obj in hashes.values():
                hash_obj.update(chunk)
    
    print(f"\n[*] File: {file_path}")
    print(f"[*] Size: {os.path.getsize(file_path)} bytes")
    print("-" * 50)
    
    results = {}
    for name, hash_obj in hashes.items():
        digest = hash_obj.hexdigest()
        results[name] = digest
        print(f"[+] {name}: {digest}")
    
    return results

def verify_integrity(file_path, known_hash, 
                     algorithm='SHA256'):
    """Verify file matches known good hash"""
    
    results = generate_hashes(file_path)
    calculated = results[algorithm]
    
    if calculated.lower() == known_hash.lower():
        print(f"\n[+] INTEGRITY VERIFIED — "
              f"Hash matches!")
    else:
        print(f"\n[!] INTEGRITY FAILURE — "
              f"Hash does NOT match!")
        print(f"    Expected:   {known_hash}")
        print(f"    Calculated: {calculated}")

# Example usage
if __name__ == "__main__":
    generate_hashes("suspicious_file.exe")
```

---

## Skills Demonstrated
- Python scripting for security automation
- API integration (VirusTotal)
- Log parsing and analysis
- IOC extraction and enrichment
- File integrity verification
- Threat detection logic

---

## Certifications Supporting This Work
- CompTIA CySA+ CS0-003
- CompTIA Security+
- MSc Cybersecurity — University of York

---

## References
- VirusTotal API: developers.virustotal.com
- MITRE ATT&CK: attack.mitre.org
- Python Docs: docs.python.org
