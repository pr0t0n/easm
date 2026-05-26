#!/usr/bin/env python3
"""
Testa o login diretamente via API
"""
import sys
import requests
import json

BACKEND_URL = "http://localhost:8001"
ADMIN_EMAIL = "admin@example.com"
ADMIN_PASSWORD = "admin123"

print("=" * 80)
print("TESTE DE LOGIN")
print("=" * 80)
print(f"\nURL: {BACKEND_URL}")
print(f"Email: {ADMIN_EMAIL}")
print(f"Senha: {ADMIN_PASSWORD}")

try:
    print("\n🔄 Tentando fazer login...")
    response = requests.post(
        f"{BACKEND_URL}/api/auth/login",
        json={
            "email": ADMIN_EMAIL,
            "password": ADMIN_PASSWORD
        },
        timeout=10
    )
    
    print(f"\n📊 Resposta:")
    print(f"  Status: {response.status_code}")
    print(f"  Headers: {dict(response.headers)}")
    
    try:
        body = response.json()
        print(f"  Body: {json.dumps(body, indent=2)}")
    except:
        print(f"  Body (raw): {response.text}")
    
    if response.status_code == 200:
        print("\n✅ LOGIN SUCESSOSO!")
        token = response.json().get("access_token")
        print(f"Access Token: {token[:50]}...")
    else:
        print(f"\n❌ ERRO NO LOGIN (Status {response.status_code})")
        
except requests.exceptions.ConnectionError as e:
    print(f"\n❌ Erro de conexão: {e}")
    print("   O backend pode não estar respondendo em http://localhost:8001")
except Exception as e:
    print(f"\n❌ Erro: {e}")
    import traceback
    traceback.print_exc()
