from __future__ import annotations

import os
import time

import requests


def main() -> None:
    base = os.getenv("E2E_API_URL", "http://localhost:8000").rstrip("/")
    email = os.environ["ADMIN_EMAIL"]
    password = os.environ["ADMIN_PASSWORD"]
    health = requests.get(f"{base}/health", timeout=10)
    health.raise_for_status()
    auth = requests.post(f"{base}/api/auth/login", json={"email": email, "password": password}, timeout=10)
    auth.raise_for_status()
    headers = {"Authorization": f"Bearer {auth.json()['access_token']}"}
    scans = requests.get(f"{base}/api/scans", headers=headers, timeout=20)
    scans.raise_for_status()
    scan_rows = scans.json()
    scan_id = int(scan_rows[0]["id"]) if scan_rows else None
    endpoints = [
        ("control_plane", f"{base}/api/dashboard/control-plane?finding_limit=200", 3.0, 500_000),
    ]
    if scan_id:
        endpoints.extend([
            ("report_contract", f"{base}/api/pentest/scans/{scan_id}/report-contract?findings_limit=200", 5.0, 2_000_000),
            ("quality", f"{base}/api/scans/{scan_id}/quality", 3.0, 200_000),
        ])
    for name, url, max_seconds, max_bytes in endpoints:
        started = time.perf_counter()
        response = requests.get(url, headers=headers, timeout=max(10, int(max_seconds * 3)))
        elapsed = time.perf_counter() - started
        response.raise_for_status()
        size = len(response.content)
        if elapsed > max_seconds:
            raise RuntimeError(f"{name} exceeded latency budget: {elapsed:.3f}s > {max_seconds:.3f}s")
        if size > max_bytes:
            raise RuntimeError(f"{name} exceeded payload budget: {size} > {max_bytes}")
        print({"endpoint": name, "seconds": round(elapsed, 3), "bytes": size, "status": response.status_code})


if __name__ == "__main__":
    main()
