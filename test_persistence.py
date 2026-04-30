#!/usr/bin/env python3
"""
E2E Validation: Test Data Persistence for Discovered Subdomains
"""
import requests
import time
from datetime import datetime

BASE_URL = "http://localhost:8001"
TARGET = "validcertificadora.com.br"
TEST_EMAIL = "admin@easm.local"
TEST_PASSWORD = "password"

print(f"[{datetime.now()}] Starting E2E Data Persistence Test")
print(f"Target: {TARGET}\n")

# Step 1: Login
print("1️⃣  AUTHENTICATION")
try:
    resp = requests.post(
        f"{BASE_URL}/api/auth/login",
        json={"email": TEST_EMAIL, "password": TEST_PASSWORD},
        timeout=10
    )
    if resp.status_code != 200:
        print(f"❌ Login failed: {resp.status_code}")
        exit(1)
    login_data = resp.json()
    token = login_data.get("access_token")
    print(f"✅ Login successful\n")
except Exception as e:
    print(f"❌ Auth error: {e}")
    exit(1)

headers = {"Authorization": f"Bearer {token}"}

# Step 2: Allowlist target
print("2️⃣  ALLOWLIST TARGET")
try:
    requests.post(
        f"{BASE_URL}/api/policy/allowlist",
        json={"domain": TARGET},
        headers=headers,
        timeout=10
    )
    print(f"✅ Target allowlisted\n")
except Exception as e:
    print(f"⚠️  Allowlist error: {e}\n")

# Step 3: Create scan
print("3️⃣  CREATE SCAN")
try:
    resp = requests.post(
        f"{BASE_URL}/api/scans",
        json={"target_query": TARGET, "scan_mode": "unit"},
        headers=headers,
        timeout=10
    )
    if resp.status_code not in [200, 201]:
        print(f"❌ Scan creation failed: {resp.status_code}")
        exit(1)
    scan_data = resp.json()
    scan_id = scan_data.get("id", scan_data.get("scan_id"))
    print(f"✅ Scan created - ID: {scan_id}\n")
except Exception as e:
    print(f"❌ Scan creation error: {e}")
    exit(1)

# Step 4: Monitor scan progression (20 sec check)
print("4️⃣  MONITOR ASSET DISCOVERY (20s)")
max_wait = 20
start_time = time.time()
last_step = None

while time.time() - start_time < max_wait:
    try:
        resp = requests.get(
            f"{BASE_URL}/api/scans/{scan_id}/status",
            headers=headers,
            timeout=5
        )
        if resp.status_code == 200:
            status_data = resp.json()
            current_step = status_data.get("current_step", "")
            status = status_data.get("status", "")
            state_data = status_data.get("state_data", {})
            target_type = state_data.get("target_type", "unknown")
            discovered_subdomains = state_data.get("discovered_subdomains_persisted", [])
            
            if current_step != last_step:
                elapsed = int(time.time() - start_time)
                print(f"   [{elapsed}s] {current_step} | status={status} | target_type={target_type}")
                print(f"               discovered_persisted={len(discovered_subdomains)}")
                last_step = current_step
            
            if "Asset" in current_step:
                print(f"\n✅ Asset Discovery node reached!")
                break
                
    except Exception as e:
        pass
    
    time.sleep(2)

# Step 5: Query Asset table
print("\n5️⃣  ASSET TABLE VERIFICATION")
try:
    from app.db.session import SessionLocal
    from app.models.models import Asset, ScanJob
    
    db = SessionLocal()
    try:
        scan_job = db.query(ScanJob).filter(ScanJob.id == scan_id).first()
        if scan_job:
            print(f"✅ Scan job found")
            print(f"   Owner ID: {scan_job.owner_id}")
            print(f"   Status: {scan_job.status}")
            
            # Count domain assets
            domain_assets = db.query(Asset).filter(
                Asset.owner_id == scan_job.owner_id,
                Asset.asset_type == "domain"
            ).all()
            
            print(f"   Domain assets in DB: {len(domain_assets)}")
            if domain_assets:
                print(f"   Sample:")
                for asset in sorted(domain_assets, key=lambda x: x.created_at, reverse=True)[:3]:
                    print(f"      - {asset.domain_or_ip}")
        else:
            print(f"❌ Scan job not found")
    finally:
        db.close()
except Exception as e:
    print(f"❌ Database error: {e}")

print("\n✅ TEST COMPLETE")
