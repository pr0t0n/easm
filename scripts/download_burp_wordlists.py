#!/usr/bin/env python3
"""
Download and organize Burp Suite wordlists from kkrypt0nn repository.
Wordlists are organized by category for use in Intruder and Repeater attacks.
"""

import os
import sys
import requests
import gzip
import shutil
from pathlib import Path
from typing import List, Tuple
from urllib.parse import urljoin

# Wordlist definitions: (category, github_path)
WORDLISTS = {
    "discovery": [
        "wordlists/discovery/directory_list_2.3_medium.txt",
        "wordlists/discovery/fuzz_php_special.txt",
        "wordlists/discovery/lfi_all.txt",
        "wordlists/discovery/top_subdomains.txt",
        "wordlists/discovery/common.txt",
    ],
    "vulnerabilities": [
        "wordlists/vulnerabilities/all_attacks.txt",
        "wordlists/vulnerabilities/directory_traversal.txt",
        "wordlists/vulnerabilities/sql.txt",
        "wordlists/vulnerabilities/sql_inj.txt",
        "wordlists/vulnerabilities/ssti.txt",
        "wordlists/vulnerabilities/xss.txt",
        "wordlists/vulnerabilities/xxe.txt",
        "wordlists/vulnerabilities/jboss.txt",
        "wordlists/vulnerabilities/sap.txt",
        "wordlists/vulnerabilities/sharepoint.txt",
        "wordlists/vulnerabilities/weblogic.txt",
        "wordlists/vulnerabilities/websphere.txt",
    ],
    "common": [
        "wordlists/discovery/apache_user_enum_2.0.txt",
        "wordlists/discovery/common_sql_tables.txt",
    ],
    "credentials": [
        "wordlists/languages/portuguese.txt",
    ],
}

# Wordlists that need .zip extraction
COMPRESSED_WORDLISTS = {
    "famous/rockyou.zip": "credentials",
}

BASE_URL = "https://raw.githubusercontent.com/kkrypt0nn/wordlists/main/"
WORDLIST_DIR = Path("/opt/burp-wordlists")


def ensure_directory(path: Path) -> None:
    """Ensure directory exists."""
    path.mkdir(parents=True, exist_ok=True)


def download_file(url: str, dest: Path, timeout: int = 30) -> bool:
    """Download file from URL to destination."""
    try:
        print(f"  Downloading: {url}")
        response = requests.get(url, timeout=timeout, allow_redirects=True)
        response.raise_for_status()
        
        dest.parent.mkdir(parents=True, exist_ok=True)
        with open(dest, 'wb') as f:
            f.write(response.content)
        
        size_kb = dest.stat().st_size / 1024
        print(f"    ✓ Saved to {dest.name} ({size_kb:.1f} KB)")
        return True
    except Exception as e:
        print(f"    ✗ Failed: {e}")
        return False


def download_wordlists() -> None:
    """Download all configured wordlists."""
    ensure_directory(WORDLIST_DIR)
    
    total_downloaded = 0
    total_failed = 0
    
    # Download text wordlists
    for category, paths in WORDLISTS.items():
        category_dir = WORDLIST_DIR / category
        ensure_directory(category_dir)
        
        print(f"\n[*] Downloading {category} wordlists...")
        for path in paths:
            filename = path.split('/')[-1]
            url = urljoin(BASE_URL, path)
            dest = category_dir / filename
            
            if download_file(url, dest):
                total_downloaded += 1
            else:
                total_failed += 1
    
    # Download compressed wordlists
    print(f"\n[*] Downloading compressed wordlists...")
    for zip_path, category in COMPRESSED_WORDLISTS.items():
        category_dir = WORDLIST_DIR / category
        ensure_directory(category_dir)
        
        filename = zip_path.split('/')[-1]
        url = urljoin(BASE_URL, zip_path)
        temp_zip = Path("/tmp") / filename
        
        if download_file(url, temp_zip):
            try:
                print(f"  Extracting: {filename}")
                with gzip.open(temp_zip, 'rb') as f_in:
                    extract_path = category_dir / filename.replace('.zip', '.txt')
                    with open(extract_path, 'wb') as f_out:
                        shutil.copyfileobj(f_in, f_out)
                print(f"    ✓ Extracted to {extract_path.name}")
                total_downloaded += 1
            except Exception as e:
                print(f"    ✗ Extraction failed: {e}")
                total_failed += 1
            finally:
                temp_zip.unlink(missing_ok=True)
        else:
            total_failed += 1
    
    # Summary
    print(f"\n[+] Download Summary:")
    print(f"  ✓ Successfully downloaded: {total_downloaded}")
    print(f"  ✗ Failed: {total_failed}")
    print(f"  📁 Wordlists saved to: {WORDLIST_DIR}")
    
    # List organized structure
    print(f"\n[+] Wordlist structure:")
    for category_dir in sorted(WORDLIST_DIR.iterdir()):
        if category_dir.is_dir():
            count = len(list(category_dir.glob("*")))
            print(f"  {category_dir.name}/ ({count} files)")
            for wl in sorted(category_dir.glob("*"))[:3]:  # Show first 3
                size = wl.stat().st_size / 1024
                print(f"    - {wl.name} ({size:.0f} KB)")
            if count > 3:
                print(f"    ... and {count - 3} more")


def create_burp_config():
    """Create Burp Suite configuration for Intruder with wordlists."""
    config_dir = Path("/opt/burp-config")
    ensure_directory(config_dir)
    
    # Create Burp config file for intruder attacks
    burp_config = config_dir / "burp-intruder-config.json"
    
    config_content = {
        "intruder": {
            "attack_types": [
                {
                    "name": "Fuzzing - Discovery",
                    "type": "sniper",
                    "wordlist": "/opt/burp-wordlists/discovery/directory_list_2.3_medium.txt",
                    "description": "Directory discovery fuzzing"
                },
                {
                    "name": "Fuzzing - PHP",
                    "type": "sniper",
                    "wordlist": "/opt/burp-wordlists/discovery/fuzz_php_special.txt",
                    "description": "PHP parameter fuzzing"
                },
                {
                    "name": "SQLi Detection",
                    "type": "sniper",
                    "wordlist": "/opt/burp-wordlists/vulnerabilities/sql_inj.txt",
                    "description": "SQL Injection payload testing"
                },
                {
                    "name": "LFI/RFI Testing",
                    "type": "sniper",
                    "wordlist": "/opt/burp-wordlists/discovery/lfi_all.txt",
                    "description": "Local File Inclusion testing"
                },
                {
                    "name": "XSS Payload Testing",
                    "type": "sniper",
                    "wordlist": "/opt/burp-wordlists/vulnerabilities/xss.txt",
                    "description": "Cross-Site Scripting payloads"
                },
                {
                    "name": "SSTI Testing",
                    "type": "sniper",
                    "wordlist": "/opt/burp-wordlists/vulnerabilities/ssti.txt",
                    "description": "Server-Side Template Injection"
                },
                {
                    "name": "Directory Traversal",
                    "type": "sniper",
                    "wordlist": "/opt/burp-wordlists/vulnerabilities/directory_traversal.txt",
                    "description": "Path traversal payload testing"
                },
            ]
        },
        "repeater": {
            "idor_testing": {
                "description": "Test for Insecure Direct Object References",
                "parameters_to_test": ["id", "user_id", "account", "object_id"],
                "techniques": [
                    "Sequential number incrementing",
                    "Hash/UUID manipulation",
                    "Timestamp-based IDs"
                ]
            },
            "sqli_testing": {
                "description": "Manual SQLi testing in Repeater",
                "payloads": "See /opt/burp-wordlists/vulnerabilities/sql_inj.txt",
                "common_parameters": ["search", "id", "q", "filter", "user"]
            }
        },
        "wordlist_categories": {
            "discovery": "/opt/burp-wordlists/discovery/",
            "vulnerabilities": "/opt/burp-wordlists/vulnerabilities/",
            "common": "/opt/burp-wordlists/common/",
            "credentials": "/opt/burp-wordlists/credentials/"
        }
    }
    
    import json
    with open(burp_config, 'w') as f:
        json.dump(config_content, f, indent=2)
    
    print(f"\n[+] Created Burp config at: {burp_config}")


if __name__ == "__main__":
    try:
        print("[*] Burp Suite Wordlist Downloader")
        print(f"[*] Target directory: {WORDLIST_DIR}\n")
        
        # Check internet connectivity
        try:
            requests.head("https://github.com", timeout=5)
        except:
            print("[!] Warning: No internet connectivity. Skipping downloads.")
            sys.exit(1)
        
        download_wordlists()
        create_burp_config()
        
        print("\n[✓] Burp wordlists setup complete!")
    except KeyboardInterrupt:
        print("\n[!] Interrupted by user.")
        sys.exit(1)
    except Exception as e:
        print(f"\n[✗] Error: {e}")
        sys.exit(1)
