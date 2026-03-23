#!/usr/bin/env python3
"""
Downloads Nuclei DAST templates from pr0t0n/secure-code-sentinel repository
to ~/.nuclei/templates/ directory.
"""

import os
import subprocess
import shutil
from pathlib import Path

def download_templates():
    """Download templates from GitHub repository"""
    home = Path.home()
    templates_dir = home / ".nuclei" / "templates"
    temp_clone_dir = home / ".nuclei" / "temp_clone"
    
    # Create .nuclei directory if it doesn't exist
    templates_dir.parent.mkdir(parents=True, exist_ok=True)
    
    print(f"[*] Target templates directory: {templates_dir}")
    print(f"[*] Temporary clone directory: {temp_clone_dir}")
    
    # Clean up any existing temp directory
    if temp_clone_dir.exists():
        print("[*] Cleaning up existing temp directory...")
        shutil.rmtree(temp_clone_dir)
    
    # Clone the repository
    print("[*] Cloning pr0t0n/secure-code-sentinel repository...")
    try:
        subprocess.run(
            [
                "git",
                "clone",
                "--depth",
                "1",
                "--filter=blob:none",
                "--sparse",
                "https://github.com/pr0t0n/secure-code-sentinel.git",
                str(temp_clone_dir),
            ],
            check=True,
            capture_output=True,
            text=True,
        )
        
        # Sparse checkout only the templates directory
        subprocess.run(
            ["git", "-C", str(temp_clone_dir), "sparse-checkout", "set", "server/dast/templates"],
            check=True,
            capture_output=True,
            text=True,
        )
        
        source_templates = temp_clone_dir / "server" / "dast" / "templates"
        
        if source_templates.exists():
            print(f"[+] Found templates at {source_templates}")
            
            # Back up existing templates if they exist
            if templates_dir.exists():
                backup_dir = templates_dir.parent / "templates_backup"
                if backup_dir.exists():
                    shutil.rmtree(backup_dir)
                shutil.move(str(templates_dir), str(backup_dir))
                print(f"[*] Backed up existing templates to {backup_dir}")
            
            # Copy new templates
            shutil.copytree(source_templates, templates_dir)
            print(f"[+] Templates copied to {templates_dir}")
            
            # Count and list templates
            template_files = list(templates_dir.rglob("*.yaml")) + list(templates_dir.rglob("*.yml"))
            print(f"[+] Total templates downloaded: {len(template_files)}")
            
            # Show first few template names
            print("[+] Sample templates:")
            for template_file in sorted(template_files)[:10]:
                relative_path = template_file.relative_to(templates_dir)
                print(f"    - {relative_path}")
            if len(template_files) > 10:
                print(f"    ... and {len(template_files) - 10} more")
        else:
            print(f"[-] Templates directory not found at {source_templates}")
            return False
            
    except subprocess.CalledProcessError as e:
        print(f"[-] Error during git clone/sparse-checkout: {e.stderr}")
        return False
    except Exception as e:
        print(f"[-] Error: {e}")
        return False
    finally:
        # Clean up temp directory
        if temp_clone_dir.exists():
            print("[*] Cleaning up temporary directory...")
            shutil.rmtree(temp_clone_dir)
    
    return True

if __name__ == "__main__":
    success = download_templates()
    exit(0 if success else 1)
