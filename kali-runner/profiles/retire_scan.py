#!/usr/bin/env python3
"""Vulnerable/outdated client-side JS component detection — GENERIC, no
target-specific knowledge. Downloads a page's same-origin <script> files
(plus any already-discovered JS URLs passed in) and runs retire.js's public
vulnerability database (jsdelivr/retirejs) against them.

Covers the OWASP "Vulnerable and Outdated Components" category for any
target with client-side JS dependencies — nothing here is specific to any
one application; it identifies a library + version and reports whatever
real CVEs/advisories retire.js's database has for that exact version.

argv[1] URL          page URL (or a direct .js URL) to scan
argv[2] EXTRA_JS_CSV optional comma-separated list of additional JS URLs
                      already discovered by other recon tools (katana,
                      linkfinder, gau, ...), widening coverage beyond what
                      a single page's <script> tags reveal
"""
import json
import os
import re
import subprocess
import sys
import tempfile
import urllib.parse
import urllib.request

URL = sys.argv[1] if len(sys.argv) > 1 else ""
EXTRA = [u.strip() for u in (sys.argv[2].split(",") if len(sys.argv) > 2 and sys.argv[2] else []) if u.strip()]


def _fetch(url: str, timeout: int = 10) -> bytes:
    req = urllib.request.Request(url, headers={"User-Agent": "Mozilla/5.0"})
    with urllib.request.urlopen(req, timeout=timeout) as resp:
        return resp.read()


def main() -> None:
    if not URL:
        print(json.dumps({"error": "no_target_url"}))
        return

    js_urls = set(EXTRA)
    if URL.lower().split("?")[0].endswith(".js"):
        js_urls.add(URL)
    else:
        try:
            html = _fetch(URL).decode("utf-8", "ignore")
        except Exception as exc:  # noqa: BLE001
            print(json.dumps({"error": f"fetch_failed: {exc}", "js_files_downloaded": 0}))
            return
        for m in re.finditer(r'<script[^>]+src=["\']([^"\']+)["\']', html, re.IGNORECASE):
            js_urls.add(urllib.parse.urljoin(URL, m.group(1)))

    workdir = tempfile.mkdtemp(prefix="retire-scan-")
    downloaded = 0
    for i, js_url in enumerate(js_urls):
        try:
            data = _fetch(js_url)
        except Exception:  # noqa: BLE001
            continue
        with open(os.path.join(workdir, f"lib_{i}.js"), "wb") as fh:
            fh.write(data)
        downloaded += 1

    if downloaded == 0:
        print(json.dumps({"error": "no_js_files_downloaded", "js_urls_tried": sorted(js_urls)[:40]}))
        return

    out_path = os.path.join(workdir, "retire_result.json")
    try:
        subprocess.run(
            [
                "retire", "--path", workdir, "--outputformat", "json",
                "--outputpath", out_path, "--severity", "none", "--includeOsv",
            ],
            capture_output=True, timeout=90, check=False,
        )
    except Exception as exc:  # noqa: BLE001
        print(json.dumps({"error": f"retire_execution_failed: {exc}", "js_files_downloaded": downloaded}))
        return

    try:
        with open(out_path) as fh:
            result = json.load(fh)
    except Exception:  # noqa: BLE001
        result = {"data": []}

    vulnerable = []
    for entry in result.get("data", []) or []:
        for r in entry.get("results", []) or []:
            for v in r.get("vulnerabilities", []) or []:
                vulnerable.append({
                    "component": r.get("component"),
                    "version": r.get("version"),
                    "severity": v.get("severity"),
                    "identifiers": v.get("identifiers", {}),
                    "info": v.get("info", []),
                })

    print(json.dumps({
        "js_files_downloaded": downloaded,
        "js_urls": sorted(js_urls)[:40],
        "vulnerable_components": vulnerable,
        "vulnerable_count": len(vulnerable),
    }, indent=2))


if __name__ == "__main__":
    main()
