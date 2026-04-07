import requests
import json

BASE_URL = "http://backend:8000"

# Try to login with different formats
test_emails = [
    "admin@easm.local",
    "admin",
    "admin@example.com"
]

for email in test_emails:
    print(f"\nTesting email: {email}")
    try:
        resp = requests.post(
            f"{BASE_URL}/api/auth/login",
            json={"email": email, "password": "password"},
            timeout=5
        )
        print(f"  Status: {resp.status_code}")
        if resp.status_code != 200:
            data = resp.json()
            print(f"  Response: {json.dumps(data, indent=2)}")
        else:
            print(f"  ✅ Success!")
    except Exception as e:
        print(f"  Error: {e}")
