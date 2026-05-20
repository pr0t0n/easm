from __future__ import annotations

import argparse
import json
import re
import socket
from collections import Counter, defaultdict
from contextlib import contextmanager
from datetime import datetime, timezone
from pathlib import Path
from typing import Any
from concurrent.futures import ThreadPoolExecutor, as_completed
from urllib.request import Request, urlopen


DEFAULT_GIST_URL = (
    "https://gist.githubusercontent.com/iamsarvagyaa/"
    "2b7b03b1dbd964efd18a506e5b82d7e6/raw/"
    "b39e12a8ea8d42ba851ec4bffb1e7a311ab5f25f/h1reports"
)
DEFAULT_SOURCE_URLS = [DEFAULT_GIST_URL]

MAX_MANIFEST_REPORT_URLS = 20_000


@contextmanager
def _prefer_ipv4_dns():
    original_getaddrinfo = socket.getaddrinfo

    def getaddrinfo_ipv4(host, port, family=0, type=0, proto=0, flags=0):  # noqa: A002
        return original_getaddrinfo(host, port, socket.AF_INET, type, proto, flags)

    socket.getaddrinfo = getaddrinfo_ipv4
    try:
        yield
    finally:
        socket.getaddrinfo = original_getaddrinfo


def _extract_report_sections(text: str) -> dict[str, str]:
    buckets: dict[str, list[str]] = {"steps_to_reproduce": [], "impact": [], "remediation": []}
    current_key: str | None = None
    current_lines: list[str] = []

    def flush() -> None:
        nonlocal current_key, current_lines
        if current_key and current_lines:
            value = "\n".join(current_lines).strip()
            if value:
                buckets[current_key].append(value)
        current_lines = []

    for raw_line in str(text or "").replace("\r\n", "\n").replace("\r", "\n").splitlines():
        line = raw_line.rstrip()
        heading = ""
        markdown = re.match(r"^\s{0,3}#{1,6}\s+(.+?)\s*$", line)
        plain = re.match(
            r"^\s*(Steps?\s+to\s+Reproduce|Reproduction\s+Steps?|Repro\s+Steps?|Proof\s+of\s+Concept|PoC|Impact|Remediation|Mitigation|Suggested\s+Mitigation/Remediation\s+Actions)\s*:?\s*$",
            line,
            re.IGNORECASE,
        )
        if markdown:
            heading = markdown.group(1)
        elif plain:
            heading = plain.group(1)
        if heading:
            flush()
            normalized = re.sub(r"[^a-z0-9]+", " ", heading.lower()).strip()
            if ("step" in normalized and ("reproduce" in normalized or "reproduction" in normalized)) or normalized in {
                "poc",
                "proof of concept",
                "proof of concept poc",
            }:
                current_key = "steps_to_reproduce"
            elif normalized.startswith("impact"):
                current_key = "impact"
            elif "remediation" in normalized or "mitigation" in normalized:
                current_key = "remediation"
            else:
                current_key = None
            continue
        if current_key:
            current_lines.append(line)
    flush()
    return {key: "\n\n".join(values).strip() for key, values in buckets.items()}


def _extract_manifest_reports(text: str, source_url: str, limit: int = MAX_MANIFEST_REPORT_URLS) -> list[dict[str, Any]]:
    reports: list[dict[str, Any]] = []
    seen: set[str] = set()
    markdown_link = re.compile(
        r"\[([^\]]+)\]\((https?://(?:www\.)?hackerone\.com/reports/(\d+)(?:\.json)?)\)",
        re.IGNORECASE,
    )
    for match in markdown_link.finditer(str(text or "")):
        report_id = match.group(3)
        url = f"https://hackerone.com/reports/{report_id}.json"
        if url in seen:
            continue
        seen.add(url)
        reports.append({"url": url, "report_id": report_id, "manifest_title": match.group(1).strip(), "source_url": source_url})
        if len(reports) >= max(1, limit):
            break
    if len(reports) >= max(1, limit):
        return reports
    for match in re.finditer(r"https?://(?:www\.)?hackerone\.com/reports/(\d+)(?:\.json)?", str(text or ""), re.IGNORECASE):
        report_id = match.group(1)
        url = f"https://hackerone.com/reports/{report_id}.json"
        if url in seen:
            continue
        seen.add(url)
        reports.append({"url": url, "report_id": report_id, "manifest_title": "", "source_url": source_url})
        if len(reports) >= max(1, limit):
            break
    return reports


def _skill_target_for_learning(vulnerability_type: str, title: str) -> dict[str, str]:
    blob = f"{vulnerability_type} {title}".lower()
    if "topinfodisclosure" in blob:
        return {"skill_id": "skill.vuln.information_disclosure", "path": "skills/vulnerability_testing/information_disclosure.md"}
    if "topbusinesslogic" in blob:
        return {"skill_id": "skill.vuln.business_logic", "path": "skills/vulnerability_testing/business_logic.md"}
    if "toprce" in blob:
        return {"skill_id": "skill.vuln.command_injection", "path": "skills/vulnerability_testing/command_injection.md"}
    if "topgraphql" in blob or "graphql" in blob:
        return {"skill_id": "skill.vuln.graphql", "path": "skills/vulnerability_testing/graphql.md"}
    if "topapi" in blob or " api " in f" {blob} " or "endpoint" in blob:
        return {"skill_id": "skill.vuln.api_security", "path": "skills/vulnerability_testing/api_security.md"}
    if "topwebcache" in blob or "web cache" in blob or "cache poisoning" in blob or "cache deception" in blob:
        return {"skill_id": "skill.vuln.web_cache", "path": "skills/vulnerability_testing/web_cache.md"}
    if "topsubdomaintakeover" in blob or "subdomain takeover" in blob or ("takeover" in blob and "subdomain" in blob):
        return {"skill_id": "skill.vuln.subdomain_takeover", "path": "skills/vulnerability_testing/subdomain_takeover.md"}
    if "topracecondition" in blob or "race condition" in blob or " race " in f" {blob} " or "toctou" in blob:
        return {"skill_id": "skill.vuln.race_condition", "path": "skills/vulnerability_testing/race_condition.md"}
    if "topaccounttakeover" in blob or "account takeover" in blob or "ato" in blob or "reset password" in blob or "password reset" in blob or "auth token theft" in blob:
        return {"skill_id": "skill.vuln.account_takeover", "path": "skills/vulnerability_testing/account_takeover.md"}
    if "oauth" in blob or "sso" in blob or "openid" in blob:
        return {"skill_id": "skill.vuln.oauth_misconfiguration", "path": "skills/vulnerability_testing/oauth_misconfiguration.md"}
    if "crlf" in blob or "header injection" in blob or "response splitting" in blob or "hyperlink injection" in blob:
        return {"skill_id": "skill.vuln.crlf_header_injection", "path": "skills/vulnerability_testing/crlf_header_injection.md"}
    if "request smuggling" in blob or "http request smuggling" in blob:
        return {"skill_id": "skill.vuln.request_smuggling", "path": "skills/vulnerability_testing/request_smuggling.md"}
    if "template injection" in blob or "ssti" in blob or "templated service" in blob:
        return {"skill_id": "skill.vuln.ssti", "path": "skills/vulnerability_testing/ssti.md"}
    if "file upload" in blob or "webshell" in blob or "upload malicious file" in blob or "dangerous type" in blob:
        return {"skill_id": "skill.vuln.file_upload", "path": "skills/vulnerability_testing/file_upload.md"}
    if "jenkins" in blob or "continuous integration" in blob or "ci " in f" {blob} " or "travis" in blob or "build logs" in blob or "grafana" in blob:
        return {"skill_id": "skill.vuln.exposed_admin_ci", "path": "skills/vulnerability_testing/exposed_admin_ci.md"}
    if "csv-injection" in blob or "csv injection" in blob or "formula injection" in blob:
        return {"skill_id": "skill.vuln.csv_formula_injection", "path": "skills/vulnerability_testing/csv_formula_injection.md"}
    if "arbitrary file read" in blob or "local files" in blob or "allowed_paths" in blob:
        return {"skill_id": "skill.vuln.path_traversal", "path": "skills/vulnerability_testing/path_traversal.md"}
    if "stored" in blob and ("xss" in blob or "cross-site scripting" in blob or "cross site scripting" in blob or "cross-site-scripting" in blob):
        return {"skill_id": "skill.stored_xss_testing", "path": "skills/vulnerability_testing/stored_xss_testing.md"}
    if "xss" in blob or "cross-site scripting" in blob or "cross site scripting" in blob or "cross-site-scripting" in blob:
        return {"skill_id": "skill.vuln.xss", "path": "skills/vulnerability_testing/xss.md"}
    if "sql" in blob or "sqli" in blob:
        return {"skill_id": "skill.vuln.sqli", "path": "skills/vulnerability_testing/sqli.md"}
    if "idor" in blob or "authorization" in blob or "object" in blob or "access control" in blob:
        return {"skill_id": "skill.idor_object_authorization", "path": "skills/vulnerability_testing/idor_object_authorization.md"}
    if "ssrf" in blob or "server-side request forgery" in blob:
        return {"skill_id": "skill.vuln.ssrf", "path": "skills/vulnerability_testing/ssrf.md"}
    if "csrf" in blob or "cross-site request forgery" in blob or "cross site request forgery" in blob:
        return {"skill_id": "skill.vuln.csrf", "path": "skills/vulnerability_testing/csrf.md"}
    if "open redirect" in blob or "tabnabbing" in blob:
        return {"skill_id": "skill.vuln.open_redirect", "path": "skills/vulnerability_testing/open_redirect.md"}
    if "clickjacking" in blob or "frame" in blob:
        return {"skill_id": "skill.vuln.clickjacking", "path": "skills/vulnerability_testing/clickjacking.md"}
    if "path traversal" in blob or "directory traversal" in blob or "file inclusion" in blob:
        return {"skill_id": "skill.vuln.path_traversal", "path": "skills/vulnerability_testing/path_traversal.md"}
    if "command injection" in blob or "os command" in blob or "code injection" in blob or "rce" in blob or "remote code execution" in blob:
        return {"skill_id": "skill.vuln.command_injection", "path": "skills/vulnerability_testing/command_injection.md"}
    if "information disclosure" in blob or "privacy violation" in blob or "expos" in blob or "leak" in blob:
        return {"skill_id": "skill.vuln.information_disclosure", "path": "skills/vulnerability_testing/information_disclosure.md"}
    if "resource consumption" in blob or "denial of service" in blob or "dos" in blob:
        return {"skill_id": "skill.vuln.resource_consumption", "path": "skills/vulnerability_testing/resource_consumption.md"}
    if "heap overflow" in blob or "buffer over" in blob or "memory corruption" in blob or "out-of-bounds" in blob or "double free" in blob or "cve-" in blob:
        return {"skill_id": "skill.vuln.component_memory_corruption", "path": "skills/vulnerability_testing/component_memory_corruption.md"}
    if "xml entity" in blob or "xxe" in blob:
        return {"skill_id": "skill.vuln.xxe", "path": "skills/vulnerability_testing/xxe.md"}
    if "deserialization" in blob or "untrusted data" in blob or "unserialize" in blob:
        return {"skill_id": "skill.vuln.deserialization", "path": "skills/vulnerability_testing/deserialization.md"}
    if "cors" in blob or "cross-origin" in blob or "cross origin" in blob:
        return {"skill_id": "skill.vuln.cors_misconfiguration", "path": "skills/vulnerability_testing/cors_misconfiguration.md"}
    if "cleartext" in blob or "plaintext" in blob or "missing encryption" in blob or "cryptographic" in blob:
        return {"skill_id": "skill.vuln.crypto_storage", "path": "skills/vulnerability_testing/crypto_storage.md"}
    if "secure design" in blob or "business logic" in blob or "privilege escalation" in blob or "time-of-check" in blob or "input validation" in blob or "read-only permissions" in blob or "user deletion" in blob or "ransomware protection" in blob or "parameter tampering" in blob or "price manipulation" in blob or "response manipulation" in blob or "captcha bypass" in blob or "reputation manipulation" in blob or "logic issue" in blob or "logic flaw" in blob:
        return {"skill_id": "skill.vuln.business_logic", "path": "skills/vulnerability_testing/business_logic.md"}
    if "topauth" in blob or "authentication" in blob or "session" in blob or "cookie" in blob:
        return {"skill_id": "skill.vuln.auth_bypass", "path": "skills/vulnerability_testing/auth_bypass.md"}
    return {"skill_id": "", "path": ""}


def _report_id_from_url(url: str) -> str:
    match = re.search(r"hackerone\.com/reports/(\d+)(?:\.json)?", str(url or ""))
    return match.group(1) if match else ""


def _read_url(url: str, timeout: int = 20) -> str:
    request = Request(
        url,
        headers={
            "User-Agent": "ScriptKidd.o RiskAnalysisLearning/1.0",
            "Accept": "application/json,text/plain,*/*",
        },
    )
    with urlopen(request, timeout=timeout) as response:
        return response.read().decode("utf-8", errors="replace")


def _fetch_report(manifest_item: dict[str, Any]) -> dict[str, Any]:
    url = str(manifest_item.get("url") or "")
    report_id = _report_id_from_url(url)
    manifest_title = str(manifest_item.get("manifest_title") or "")
    source_url = str(manifest_item.get("source_url") or "")
    fallback_target = _skill_target_for_learning("", f"{manifest_title} {source_url}")
    try:
        payload = json.loads(_read_url(url, timeout=20))
        if not isinstance(payload, dict):
            return {
                "ok": False,
                "report_id": report_id,
                "url": url,
                "source_url": source_url,
                "manifest_title": manifest_title,
                "target_skill_id": fallback_target.get("skill_id") or "",
                "target_skill_path": fallback_target.get("path") or "",
                "error": "non_object_json",
            }
        weakness = payload.get("weakness") if isinstance(payload.get("weakness"), dict) else {}
        title = str(payload.get("title") or "")
        vulnerability_type = str(weakness.get("name") or "")
        body = str(payload.get("vulnerability_information") or "")
        target = _skill_target_for_learning(vulnerability_type, title)
        sections = _extract_report_sections(body)
        return {
            "ok": True,
            "report_id": report_id,
            "url": url,
            "source_url": source_url,
            "manifest_title": manifest_title,
            "title": title,
            "vulnerability_type": vulnerability_type or "unknown",
            "target_skill_id": target.get("skill_id") or "",
            "target_skill_path": target.get("path") or "",
            "has_steps_to_reproduce": bool(sections.get("steps_to_reproduce")),
            "body_length": len(body),
        }
    except Exception as exc:  # noqa: BLE001
        return {
            "ok": False,
            "report_id": report_id,
            "url": url,
            "source_url": source_url,
            "manifest_title": manifest_title,
            "title": manifest_title,
            "vulnerability_type": "manifest_title_only",
            "target_skill_id": fallback_target.get("skill_id") or "",
            "target_skill_path": fallback_target.get("path") or "",
            "has_steps_to_reproduce": False,
            "body_length": 0,
            "error": str(exc)[:240],
        }


def analyze_manifests(urls: list[str], limit: int | None, concurrency: int) -> dict[str, Any]:
    with _prefer_ipv4_dns():
        manifest_items: list[dict[str, Any]] = []
        seen: set[str] = set()
        per_source_limit = limit or MAX_MANIFEST_REPORT_URLS
        for url in urls:
            manifest_text = _read_url(url, timeout=20)
            for item in _extract_manifest_reports(manifest_text, source_url=url, limit=per_source_limit):
                if item["url"] in seen:
                    continue
                seen.add(item["url"])
                manifest_items.append(item)
        rows: list[dict[str, Any]] = []
        with ThreadPoolExecutor(max_workers=max(1, concurrency)) as pool:
            futures = [pool.submit(_fetch_report, item) for item in manifest_items]
            for future in as_completed(futures):
                rows.append(future.result())

    ok_rows = [row for row in rows if row.get("ok")]
    failed_rows = [row for row in rows if not row.get("ok")]
    weakness_counts = Counter(str(row.get("vulnerability_type") or "unknown") for row in ok_rows)
    skill_counts = Counter(str(row.get("target_skill_id") or "unmapped") for row in rows)
    source_counts = Counter(str(row.get("source_url") or "unknown") for row in rows)
    failure_counts = Counter(str(row.get("status_code") or row.get("error") or "unknown_error").split(":", 1)[0] for row in failed_rows)
    steps_by_skill: dict[str, Counter] = defaultdict(Counter)
    examples: dict[str, list[dict[str, Any]]] = defaultdict(list)
    for row in rows:
        skill_id = str(row.get("target_skill_id") or "unmapped")
        steps_by_skill[skill_id]["with_steps" if row.get("has_steps_to_reproduce") else "without_steps"] += 1
        if len(examples[skill_id]) < 5:
            examples[skill_id].append(
                {
                    "report_id": row.get("report_id"),
                    "title": row.get("title") or row.get("manifest_title"),
                    "vulnerability_type": row.get("vulnerability_type"),
                    "source_url": row.get("source_url"),
                    "has_steps_to_reproduce": row.get("has_steps_to_reproduce"),
                }
            )

    return {
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "source_urls": urls,
        "requested_limit": limit or "all",
        "manifest_report_urls": len(manifest_items),
        "fetched_ok": len(ok_rows),
        "fetch_failed": len(rows) - len(ok_rows),
        "source_counts": dict(source_counts.most_common()),
        "failure_counts": dict(failure_counts.most_common(20)),
        "failed_samples": failed_rows[:20],
        "weakness_counts": dict(weakness_counts.most_common()),
        "skill_counts": dict(skill_counts.most_common()),
        "steps_to_reproduce_by_skill": {skill: dict(counter) for skill, counter in steps_by_skill.items()},
        "unmapped_examples": examples.get("unmapped", []),
        "examples_by_skill": dict(examples),
        "coverage_gaps": [
            key
            for key, _count in skill_counts.most_common()
            if key == "unmapped"
        ],
    }


def main() -> None:
    parser = argparse.ArgumentParser(description="Analyze HackerOne manifest coverage against local Skill markdowns.")
    parser.add_argument("--url", action="append", dest="urls", help="Manifest/raw URL. Can be repeated.")
    parser.add_argument("--limit", type=int, default=0, help="0 means all report URLs in the manifest.")
    parser.add_argument("--concurrency", type=int, default=25)
    parser.add_argument("--output", default="docs/hackerone_gist_skill_coverage.json")
    args = parser.parse_args()

    result = analyze_manifests(args.urls or DEFAULT_SOURCE_URLS, args.limit or None, args.concurrency)
    output = Path(args.output)
    output.parent.mkdir(parents=True, exist_ok=True)
    output.write_text(json.dumps(result, indent=2, ensure_ascii=False), encoding="utf-8")
    print(json.dumps({k: result[k] for k in ["manifest_report_urls", "fetched_ok", "fetch_failed", "skill_counts", "coverage_gaps"]}, indent=2, ensure_ascii=False))


if __name__ == "__main__":
    main()
