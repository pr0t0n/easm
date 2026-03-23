#!/usr/bin/env python3
"""Download dos templates DAST do secure-code-sentinel para ~/.nuclei/templates/."""

import shutil
import tempfile
import urllib.request
import zipfile
from pathlib import Path


ARCHIVE_URL = "https://codeload.github.com/pr0t0n/secure-code-sentinel/zip/refs/heads/main"
ARCHIVE_ROOT = "secure-code-sentinel-main"
TEMPLATES_SUBPATH = Path("server") / "dast" / "templates"

def download_templates() -> bool:
    """Download templates from GitHub codeload and copy to nuclei templates folder."""
    home = Path.home()
    templates_dir = home / ".nuclei" / "templates"
    temp_dir = Path(tempfile.mkdtemp(prefix="nuclei-templates-"))
    archive_path = temp_dir / "secure-code-sentinel-main.zip"

    templates_dir.parent.mkdir(parents=True, exist_ok=True)

    print(f"[*] Target templates directory: {templates_dir}")
    print(f"[*] Temporary directory: {temp_dir}")

    try:
        print("[*] Downloading template archive...")
        urllib.request.urlretrieve(ARCHIVE_URL, archive_path)

        print("[*] Extracting archive...")
        with zipfile.ZipFile(archive_path, "r") as zf:
            zf.extractall(temp_dir)

        source_templates = temp_dir / ARCHIVE_ROOT / TEMPLATES_SUBPATH

        if source_templates.exists():
            print(f"[+] Found templates at {source_templates}")

            if templates_dir.exists():
                backup_dir = templates_dir.parent / "templates_backup"
                if backup_dir.exists():
                    shutil.rmtree(backup_dir)
                shutil.move(str(templates_dir), str(backup_dir))
                print(f"[*] Backed up existing templates to {backup_dir}")

            shutil.copytree(source_templates, templates_dir)
            print(f"[+] Templates copied to {templates_dir}")

            template_files = list(templates_dir.rglob("*.yaml")) + list(templates_dir.rglob("*.yml"))
            print(f"[+] Total templates downloaded: {len(template_files)}")

            print("[+] Sample templates:")
            for template_file in sorted(template_files)[:10]:
                relative_path = template_file.relative_to(templates_dir)
                print(f"    - {relative_path}")
            if len(template_files) > 10:
                print(f"    ... and {len(template_files) - 10} more")
        else:
            print(f"[-] Templates directory not found at {source_templates}")
            return False

    except Exception as e:
        print(f"[-] Error: {e}")
        return False
    finally:
        if temp_dir.exists():
            print("[*] Cleaning up temporary directory...")
            shutil.rmtree(temp_dir)

    return True

if __name__ == "__main__":
    success = download_templates()
    exit(0 if success else 1)
