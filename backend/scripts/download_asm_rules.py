#!/usr/bin/env python3
"""
Download ASM rules.json from pr0t0n/secure-code-sentinel repository
and store locally for worker analysis.
"""

import json
import shutil
import tempfile
import urllib.request
import zipfile
from pathlib import Path


ARCHIVE_URL = "https://codeload.github.com/pr0t0n/secure-code-sentinel/zip/refs/heads/main"
ARCHIVE_ROOT = "secure-code-sentinel-main"
RULES_SUBPATH = Path("src") / "rules" / "asm"


def download_asm_rules() -> bool:
    """Download ASM rules from GitHub and store locally."""
    home = Path.home()
    rules_dir = home / ".easm" / "rules"
    temp_dir = Path(tempfile.mkdtemp(prefix="asm-rules-"))
    archive_path = temp_dir / "secure-code-sentinel-main.zip"

    rules_dir.parent.mkdir(parents=True, exist_ok=True)

    print(f"[*] Target rules directory: {rules_dir}")
    print(f"[*] Temporary directory: {temp_dir}")

    try:
        print("[*] Downloading rules archive...")
        urllib.request.urlretrieve(ARCHIVE_URL, archive_path)

        print("[*] Extracting archive...")
        with zipfile.ZipFile(archive_path, "r") as zf:
            zf.extractall(temp_dir)

        source_rules = temp_dir / ARCHIVE_ROOT / RULES_SUBPATH

        if source_rules.exists():
            print(f"[+] Found rules at {source_rules}")

            if rules_dir.exists():
                backup_dir = rules_dir.parent / "rules_backup"
                if backup_dir.exists():
                    shutil.rmtree(backup_dir)
                shutil.move(str(rules_dir), str(backup_dir))
                print(f"[*] Backed up existing rules to {backup_dir}")

            shutil.copytree(source_rules, rules_dir)
            print(f"[+] Rules copied to {rules_dir}")

            rule_files = list(rules_dir.rglob("*.json"))
            print(f"[+] Total rule files downloaded: {len(rule_files)}")

            print("[+] Sample rules:")
            for rule_file in sorted(rule_files)[:10]:
                relative_path = rule_file.relative_to(rules_dir)
                print(f"    - {relative_path}")
            if len(rule_files) > 10:
                print(f"    ... and {len(rule_files) - 10} more")

            # Verify rules integrity
            total_rules = 0
            for rule_file in rule_files:
                try:
                    with open(rule_file) as f:
                        data = json.load(f)
                        if isinstance(data, list):
                            total_rules += len(data)
                        else:
                            total_rules += 1
                except json.JSONDecodeError as e:
                    print(f"[!] Invalid JSON in {rule_file}: {e}")

            print(f"[+] Total rule definitions loaded: {total_rules}")
            return True
        else:
            print(f"[-] Rules directory not found at {source_rules}")
            return False

    except Exception as e:
        print(f"[-] Error: {e}")
        return False
    finally:
        if temp_dir.exists():
            print("[*] Cleaning up temporary directory...")
            shutil.rmtree(temp_dir)


if __name__ == "__main__":
    success = download_asm_rules()
    exit(0 if success else 1)
